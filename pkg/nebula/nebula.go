package nebula

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/aRestless/nexus/pkg/client"
	"github.com/aRestless/nexus/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/cert"
	"github.com/slackhq/nebula/config"
	"golang.org/x/crypto/curve25519"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"maps"
	"net/netip"
	"os"
	"path"
	"slices"
	"time"
)

type Control struct {
	l               *logrus.Logger
	ctx             context.Context
	cancel          context.CancelFunc
	nebulaCtrl      *nebula.Control
	nebulaCfg       *config.C
	amLighthouse    bool
	lighthouseAddr  netip.AddrPort
	client          NexusServerClient
	network         string
	publicKey       []byte
	curve           cert.Curve
	cert            []byte
	ca              []byte
	certPath        string
	caPath          string
	addedConfigPath string
	pullRoutes      []netip.Prefix
	pushRoutes      []netip.Prefix
	unsafeRoutes    []UnsafeRoute
	revocations     []string
	lighthouses     map[netip.Addr]netip.AddrPort
	addedConfig     AddedConfig
}

type NexusServerClient interface {
	GetClientNetwork(network string) (server.ClientNetworkResponse, error)
	GetClientNetworkCA(network string) (server.GetCAResponse, error)
	GetClientNetworkCertificate(network, certHash string) (server.GetCertificateResponse, error)
	CreateClientNetworkCertificate(network string, request server.CreateCertificateRequest) (server.CreateCertificateResponse, error)
	ListClientNetworkRevocations(network string) (server.ListRevocationsResponse, error)
	ListClientNetworkLighthouses(network string) (server.ListLighthousesResponse, error)
	ListClientNetworkRouters(network string) (server.ListRoutersResponse, error)
	CreateClientNetworkLighthouse(network string, request server.CreateLighthouseRequest) (server.CreateLighthouseResponse, error)
	CreateClientNetworkRouter(network string, request server.CreateRouterRequest) (server.CreateRouterResponse, error)
}

func Main(client NexusServerClient, configDir string, network string, lighthouseAddrPort netip.AddrPort, pullRoutes, pushRoutes []netip.Prefix, l *logrus.Logger) (*Control, error) {
	c := config.NewC(l)
	err := c.Load(configDir)
	if err != nil {
		return nil, fmt.Errorf("loading nebula config: %v", err)
	}

	keyPath := c.GetString("pki.key", "")
	if keyPath == "" {
		return nil, fmt.Errorf("pki.key missing from config")
	}

	err = createNebulaKey(keyPath)

	amLighthouse := c.GetBool("lighthouse.am_lighthouse", false)
	if amLighthouse && (!lighthouseAddrPort.IsValid() || lighthouseAddrPort.Addr().IsUnspecified()) {
		return nil, fmt.Errorf("is lighthouse but lighthouse address unspecified")
	}

	ctrl := &Control{
		l:               l,
		nebulaCtrl:      nil,
		nebulaCfg:       c,
		amLighthouse:    amLighthouse,
		lighthouseAddr:  lighthouseAddrPort,
		client:          client,
		network:         network,
		certPath:        path.Join(path.Dir(keyPath), fmt.Sprintf("%s.crt", network)),
		caPath:          path.Join(path.Dir(keyPath), fmt.Sprintf("%s.ca.crt", network)),
		addedConfigPath: path.Join(configDir, fmt.Sprintf("zz_%s.yaml", network)),
		pullRoutes:      pullRoutes,
		pushRoutes:      pushRoutes,
	}
	log.Println("added config path: ", ctrl.addedConfigPath)

	err = createNebulaKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("create key: %v", err)
	}

	err = loadKeys(ctrl, keyPath)
	if err != nil {
		return nil, fmt.Errorf("loading keys: %v", err)
	}

	err = ctrl.loadAddedConfig()
	if err != nil {
		ctrl.waitForNetwork()
		err = ctrl.updateCA()
		if err != nil {
			return nil, fmt.Errorf("update CA: %w", err)
		}

		err = ctrl.update(true)
		if err != nil {
			return nil, fmt.Errorf("update: %w", err)
		}
	}

	ctrl.nebulaCtrl, err = nebula.Main(ctrl.nebulaCfg, false, "unknown", l, nil)
	if err != nil {
		return nil, fmt.Errorf("nebula main: %w", err)
	}

	return ctrl, nil
}

func (c *Control) loadAddedConfig() error {
	b, err := os.ReadFile(c.addedConfigPath)
	if err != nil {
		return fmt.Errorf("load existing config: %w", err)
	}

	err = yaml.Unmarshal(b, &c.addedConfig)
	if err != nil {
		return fmt.Errorf("unmarshal yaml of existing config: %w", err)
	}

	return nil
}

func (c *Control) waitForNetwork() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		c.l.Debugf("Waiting for network %s\n", c.network)
		_, err := c.client.GetClientNetwork(c.network)
		if err == nil {
			c.l.Debugf("Received network %s\n", c.network)
			return
		}

		c.l.Errorf("get client network: %v", err)
		<-t.C
	}
}

func loadKeys(c *Control, privateKeyPath string) error {
	b, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("reading private key: %v", err)
	}

	privKey, _, curve, err := cert.UnmarshalPrivateKey(b)
	if err != nil {
		return fmt.Errorf("unmarshalling private key: %v", err)
	}

	var pubKey []byte
	switch curve {
	case cert.Curve_CURVE25519:
		pubKey, err = curve25519.X25519(privKey, curve25519.Basepoint)
		if err != nil {
			return fmt.Errorf("generating X25519 public key: %v", err)
		}
	case cert.Curve_P256:
		pk, err := ecdh.P256().NewPrivateKey(privKey)
		if err != nil {
			return fmt.Errorf("loading P256 private key: %v", err)
		}

		pubKey = pk.PublicKey().Bytes()
	default:
		return fmt.Errorf("unknown curve: %s", curve.String())
	}

	c.curve = curve
	c.publicKey = pubKey

	return nil
}

func (c *Control) updateCA() error {
	resp, err := c.client.GetClientNetworkCA(c.network)
	if err != nil {
		return fmt.Errorf("get CA: %w", err)
	}

	err = os.WriteFile(c.caPath, resp.PEM, 0600)
	if err != nil {
		return fmt.Errorf("write CA file: %w", err)
	}

	return nil
}

func (c *Control) update(forceWrite bool) error {
	updatedCerts, err := c.updateCertificate()
	if err != nil {
		return fmt.Errorf("updating certficiate: %v", err)
	}

	updatedRevocations, err := c.updateRevocations()
	if err != nil {
		return fmt.Errorf("updating revocations: %v", err)
	}

	updatedLighthouses, err := c.updateLighthouses()
	if err != nil {
		return fmt.Errorf("updating lighthouses: %v", err)
	}

	updatedRoutes, err := c.updatePulledRoutes()
	if err != nil {
		return fmt.Errorf("updating pullRoutes: %v", err)
	}

	err = c.updateLighthouseEntry()

	if forceWrite || updatedRevocations || updatedLighthouses || updatedRoutes {
		err = c.writeConfig()
		if err != nil {
			return fmt.Errorf("write config: %w", err)
		}
	}

	if forceWrite || updatedCerts || updatedRevocations || updatedLighthouses || updatedRoutes {
		c.nebulaCfg.ReloadConfig()
	}

	err = c.updatePushedRoutes()
	if err != nil {
		c.l.Error(err)
	}

	return nil
}

func (c *Control) writeConfig() error {
	staticHostMap := make(map[netip.Addr][]netip.AddrPort, len(c.lighthouses))
	var lighthouses []netip.Addr
	for k, v := range c.lighthouses {
		staticHostMap[k] = []netip.AddrPort{v}
		lighthouses = append(lighthouses, k)
	}

	c.addedConfig = AddedConfig{
		PKI: PKI{
			CA:                c.caPath,
			Cert:              c.certPath,
			Blocklist:         c.revocations,
			DisconnectInvalid: true,
		},
		StaticHostMap: staticHostMap,
		Lighthouse: Lighthouse{
			Hosts: lighthouses,
		},
		Tun: Tun{
			Dev:          fmt.Sprintf("nebula-%s", c.network),
			UnsafeRoutes: c.unsafeRoutes,
		},
	}

	b, err := yaml.Marshal(c.addedConfig)
	if err != nil {
		return fmt.Errorf("marshal added config: %w", err)
	}

	err = os.WriteFile(c.addedConfigPath, b, 0600)
	if err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

func (c *Control) updateCertificate() (wasUpdated bool, err error) {
	needsRenew, err := c.certificateNeedsRenew()
	if err != nil {
		return false, fmt.Errorf("certificate needs renew: %w", err)
	}

	if !needsRenew {
		return false, nil
	}

	err = c.renewCertificate()
	if err != nil {
		return false, fmt.Errorf("renew certificate: %w", err)
	}

	return true, nil
}

func (c *Control) renewCertificate() error {
	pubKeyPEM := cert.MarshalPublicKey(c.curve, c.publicKey)

	resp, err := c.client.CreateClientNetworkCertificate(c.network, server.CreateCertificateRequest{PubPEM: pubKeyPEM})
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	return os.WriteFile(c.certPath, resp.PEM, 0600)
}

func (c *Control) certificateNeedsRenew() (bool, error) {
	if _, err := os.Stat(c.certPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("file stat for %s: %w", c.certPath, err)
		}

		return true, nil
	}

	certHash, err := c.getCertHash()
	if err != nil {
		return false, fmt.Errorf("cert hash: %w", err)
	}

	resp, err := c.client.GetClientNetworkCertificate(c.network, certHash)
	if err != nil {
		if errors.Is(err, client.ErrorNotFound) {
			return true, nil
		}

		return false, fmt.Errorf("get certificate: %w", err)
	}

	return resp.RenewableAfter.Before(time.Now()), nil
}

func (c *Control) updateRevocations() (wasUpdated bool, err error) {
	resp, err := c.client.ListClientNetworkRevocations(c.network)
	if err != nil {
		return false, fmt.Errorf("list revocations: %w", err)
	}

	var revokedHashes []string
	for _, revocation := range resp.Items {
		revokedHashes = append(revokedHashes, revocation.Hash)
	}

	slices.Sort(revokedHashes)

	if slices.Equal(revokedHashes, c.revocations) {
		return false, nil
	}

	c.revocations = revokedHashes
	return true, nil
}

func (c *Control) updateLighthouses() (wasUpdated bool, err error) {
	if c.amLighthouse {
		changed := len(c.lighthouses) > 0
		c.lighthouses = nil

		return changed, nil
	}

	resp, err := c.client.ListClientNetworkLighthouses(c.network)
	if err != nil {
		return false, fmt.Errorf("list lighthouses: %w", err)
	}

	lighthouseHostMap := make(map[netip.Addr]netip.AddrPort, len(resp.Items))
	for _, lh := range resp.Items {
		lighthouseHostMap[lh.NebulaIP] = lh.PublicAddr
	}

	if maps.Equal(lighthouseHostMap, c.lighthouses) {
		return false, nil
	}

	c.lighthouses = lighthouseHostMap
	return true, nil
}

func (c *Control) updatePulledRoutes() (wasUpdated bool, err error) {
	if len(c.pullRoutes) == 0 {
		changed := len(c.unsafeRoutes) != 0
		c.unsafeRoutes = nil
		return changed, nil
	}

	resp, err := c.client.ListClientNetworkRouters(c.network)
	if err != nil {
		return false, fmt.Errorf("list lighthouses: %w", err)
	}

	unsafeRoutesMap := make(map[string]UnsafeRoute)
	for _, router := range resp.Items {
		if !c.wantsRouteFor(router.Subnet) {
			continue
		}

		unsafeRoutesMap[router.Subnet.String()] = UnsafeRoute{
			Route:   router.Subnet.String(),
			Via:     router.NebulaIP.String(),
			Metric:  100,
			MTU:     1300,
			Install: true,
		}
	}

	var unsafeRoutes []UnsafeRoute
	for _, v := range unsafeRoutesMap {
		unsafeRoutes = append(unsafeRoutes, v)
	}

	slices.SortFunc(unsafeRoutes, func(a, b UnsafeRoute) int {
		if a.Route < b.Route {
			return -1
		}

		if b.Route < a.Route {
			return 1
		}

		return 0
	})

	if slices.Equal(unsafeRoutes, c.unsafeRoutes) {
		return false, nil
	}

	c.unsafeRoutes = unsafeRoutes

	return true, nil
}

func (c *Control) updatePushedRoutes() error {
	for _, pushRoute := range c.pushRoutes {
		c.l.Info("pushing", pushRoute.String())
		req := server.CreateRouterRequest{Subnet: pushRoute}
		_, err := c.client.CreateClientNetworkRouter(c.network, req)
		if err != nil {
			return fmt.Errorf("create client network router: %w", err)
		}
	}

	return nil
}

func (c *Control) wantsRouteFor(prefix netip.Prefix) bool {
	for _, route := range c.pullRoutes {
		if prefix.String() == route.String() {
			return true
		}
	}

	return false
}

func (c *Control) getCertHash() (string, error) {
	b, err := os.ReadFile(c.certPath)
	if err != nil {
		return "", fmt.Errorf("read certificate file: %w", err)
	}

	nc, _, err := cert.UnmarshalNebulaCertificateFromPEM(b)
	if err != nil {
		return "", fmt.Errorf("unmarshal certificate: %w", err)
	}

	return nc.Sha256Sum()
}

func (c *Control) updateLighthouseEntry() error {
	if !c.amLighthouse {
		return nil
	}

	req := server.CreateLighthouseRequest{PublicAddr: c.lighthouseAddr}

	_, err := c.client.CreateClientNetworkLighthouse(c.network, req)
	if err != nil {
		return fmt.Errorf("create lighthouse entry: %w", err)
	}

	return nil
}

func (c *Control) Start() {
	c.nebulaCtrl.Start()

	go func() {
		err := c.update(false)
		if err != nil {
			c.l.Errorf("update: %v", err)
		}

		t := time.NewTicker(5 * time.Minute)
		for {
			select {
			case <-c.nebulaCtrl.Context().Done():
				return
			case <-t.C:
				err := c.update(false)
				if err != nil {
					c.l.Errorf("ticker update: %v", err)
				}
			}
		}
	}()
}

func (c *Control) Stop() {
	c.nebulaCtrl.Stop()
}

func (c *Control) ShutdownBlock() {
	c.nebulaCtrl.ShutdownBlock()
}

func createNebulaKey(keyPath string) error {
	_, err := os.Stat(keyPath)
	if err == nil {
		return nil
	}

	if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("file stat for %s: %w", keyPath, err)
	}

	_, priv := x25519Keypair()

	curve := cert.Curve_CURVE25519
	err = os.WriteFile(keyPath, cert.MarshalPrivateKey(curve, priv), 0600)
	if err != nil {
		return fmt.Errorf("write key file %s: %w", keyPath, err)
	}

	return nil
}

func x25519Keypair() ([]byte, []byte) {
	privkey := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privkey); err != nil {
		panic(err)
	}

	pubkey, err := curve25519.X25519(privkey, curve25519.Basepoint)
	if err != nil {
		panic(err)
	}

	return pubkey, privkey
}
