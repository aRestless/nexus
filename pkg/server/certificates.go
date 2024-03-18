package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	hash := chi.URLParam(r, "hash")

	var certificate model.Certificate
	res = s.db.First(&certificate,
		"network_id = ? AND client_id = ? AND hash = ?",
		network.ID,
		clientNetwork.ClientID,
		hash,
	)
	if res.Error != nil {
		if errors.Is(res.Error, gorm.ErrRecordNotFound) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		s.handleErr(fmt.Errorf("finding certificate: %w", res.Error), w)
		return
	}

	resp := GetCertificateResponse{
		Address:        certificate.Address.ToNetip(),
		Hash:           certificate.Hash,
		Groups:         strings.Split(certificate.Groups, ","),
		NotAfter:       certificate.NotAfter,
		RevokedAfter:   certificate.RevokedAfter,
		RenewableAfter: certificate.RenewableAfter,
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	var certificates []model.Certificate
	res = s.db.Find(&certificates,
		"network_id = ? AND client_id = ? AND revoked_after > ?",
		network.ID,
		clientNetwork.ClientID,
		time.Now(),
	)
	if res.Error != nil {
		s.handleErr(fmt.Errorf("finding certificates: %w", res.Error), w)
		return
	}

	resp := ListCertificatesResponse{}
	for _, c := range certificates {
		resp.Items = append(resp.Items, GetCertificateResponse{
			Address:        c.Address.ToNetip(),
			Hash:           c.Hash,
			Groups:         strings.Split(c.Groups, ","),
			NotAfter:       c.NotAfter,
			RevokedAfter:   c.RevokedAfter,
			RenewableAfter: c.RenewableAfter,
		})
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	canRenew, err := s.canRenew(clientNetwork)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	if !canRenew {
		w.WriteHeader(http.StatusConflict)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		s.handleErr(fmt.Errorf("reading body: %w", err), w)
		return
	}

	var createCertificateRequest CreateCertificateRequest
	err = json.Unmarshal(body, &createCertificateRequest)
	if err != nil {
		s.handleErr(fmt.Errorf("unmarshal json: %w", err), w)
		return
	}

	pub, _, curve, err := cert.UnmarshalPublicKey(createCertificateRequest.PubPEM)
	if err != nil {
		s.handleErr(fmt.Errorf("unmarshal public key: %w", err), w)
		return
	}

	issuer, err := s.ca.cert.Sha256Sum()
	if err != nil {
		s.handleErr(fmt.Errorf("computing CA certificate hash sum: %w", err), w)
		return
	}

	// FIXME really ugly conversion
	networkPrefix := netip.Prefix(network.Prefix)
	addr := netip.Addr(clientNetwork.Address)

	prefix, err := addr.Prefix(networkPrefix.Bits())
	if err != nil {
		s.handleErr(fmt.Errorf("computing prefix: %w", err), w)
		return
	}

	var subnets []*net.IPNet
	for _, sn := range clientNetwork.Subnets {
		ipnet := prefix2IPNet(sn.ToNetip())
		subnets = append(subnets, &ipnet)
	}

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name: c.PublicKeyHash.String,
			Ips: []*net.IPNet{
				{
					IP:   addr2NetIP(addr),
					Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen()),
				},
			},
			Subnets:   subnets,
			Groups:    strings.Split(clientNetwork.Groups, ","),
			NotBefore: time.Now(),
			NotAfter:  time.Now().Add(90 * 24 * time.Hour),
			PublicKey: pub,
			Curve:     curve,
			IsCA:      false,
			Issuer:    issuer,
		},
	}

	err = nc.Sign(curve, s.ca.key)
	if err != nil {
		s.handleErr(fmt.Errorf("signing : %w", err), w)
		return
	}

	hashSum, err := nc.Sha256Sum()
	if err != nil {
		s.handleErr(fmt.Errorf("computing certificate hash sum: %w", err), w)
		return
	}

	err = s.revokeOtherIn(clientNetwork, 5*time.Minute, hashSum)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	modelAddr, err := netip2Addr(nc.Details.Ips[0].IP)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	certificate := model.Certificate{
		Address:        model.Addr(modelAddr),
		Hash:           hashSum,
		Groups:         clientNetwork.Groups,
		NotAfter:       nc.Details.NotAfter,
		RevokedAfter:   nc.Details.NotAfter,
		RenewableAfter: nc.Details.NotAfter.AddDate(0, 0, -30),
		NetworkID:      network.ID,
		ClientID:       c.ID,
	}

	res = s.db.Create(&certificate)
	if res.Error != nil {
		s.handleErr(fmt.Errorf("create certificate DB entry: %w", err), w)
		return
	}

	resp := CreateCertificateResponse{
		GetCertificateResponse: GetCertificateResponse{
			Address:        certificate.Address.ToNetip(),
			Hash:           certificate.Hash,
			Groups:         strings.Split(clientNetwork.Groups, ","),
			NotAfter:       certificate.NotAfter,
			RevokedAfter:   certificate.RevokedAfter,
			RenewableAfter: certificate.RenewableAfter,
		},
	}
	resp.PEM, err = nc.MarshalToPEM()
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling certificate: %w", err), w)
		return
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusCreated)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) listRevocations(w http.ResponseWriter, r *http.Request) {
	c := s.authenticateClient(r, false)
	if c == nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	networkName := chi.URLParam(r, "network")
	var network model.Network
	res := s.db.First(&network, "name = ?", networkName)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid network: %s", networkName), w)
		return
	}

	var clientNetwork model.ClientNetwork
	res = s.db.First(&clientNetwork, "network_id = ? AND client_id = ?", network.ID, c.ID)
	if res.RowsAffected != 1 {
		s.handleErr(fmt.Errorf("invalid client network %s for client %s", networkName, c.PublicKeyHash.String), w)
		return
	}

	var revokedCertificates []model.Certificate
	res = s.db.Find(&revokedCertificates,
		"network_id = ? AND revoked_after < ? AND not_after > ?",
		network.ID,
		time.Now(),
		time.Now(),
	)
	if res.Error != nil {
		s.handleErr(fmt.Errorf("finding revoked certificates: %w", res.Error), w)
		return
	}

	resp := ListRevocationsResponse{}
	for _, c := range revokedCertificates {
		resp.Items = append(resp.Items, Revocation{Hash: c.Hash})
	}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(fmt.Errorf("marshalling response : %w", err), w)
		return
	}

	w.WriteHeader(http.StatusOK)
	_, err = w.Write(b)
	if err != nil {
		s.handleErr(fmt.Errorf("flushing response : %w", err), w)
		return
	}
}

func (s *Server) canRenew(clientNetwork model.ClientNetwork) (bool, error) {
	var count int64
	res := s.db.Model(&model.Certificate{}).Where(
		"groups = ? AND client_id = ? AND network_id = ? and renewable_after > ? and revoked_after > ?",
		clientNetwork.Groups,
		clientNetwork.ClientID,
		clientNetwork.NetworkID,
		time.Now(),
		time.Now(),
	).Count(&count)

	if res.Error != nil {
		return false, fmt.Errorf("counting certificates: %w", res.Error)
	}

	return count < 1, nil
}

func (s *Server) revokeOtherIn(clientNetwork model.ClientNetwork, after time.Duration, newHash string) error {
	res := s.db.Model(&model.Certificate{}).Where(
		"client_id = ? AND network_id = ? AND revoked_after > ? AND hash != ?", clientNetwork.ClientID,
		clientNetwork.NetworkID,
		time.Now().Add(after),
		newHash,
	).Updates(map[string]any{
		"revoked_after":   time.Now().Add(after),
		"renewable_after": time.Now(),
	})

	return res.Error
}

func ipnet2Prefix(ipn net.IPNet) netip.Prefix {
	addr, _ := netip.AddrFromSlice(ipn.IP)
	cidr, _ := ipn.Mask.Size()
	return netip.PrefixFrom(addr, cidr)
}

func prefix2IPNet(prefix netip.Prefix) net.IPNet {
	addr := prefix.Addr() // extract the address portion of the prefix
	pLen := 128           // plen is the total size of the subnet mask
	if addr.Is4() {
		pLen = 32
	}
	ones := prefix.Bits()            // ones is the portion of the mask that's set
	ip := net.IP(addr.AsSlice())     // convert the address portion to net.IP
	mask := net.CIDRMask(ones, pLen) // create a net.IPMask
	return net.IPNet{                // and construct the final IPNet
		IP:   ip,
		Mask: mask,
	}
}

// convert a netip.Addr to net.IP
func addr2NetIP(addr netip.Addr) net.IP {
	return addr.AsSlice()
}

// convert net.IP to netip.Addr
func netip2Addr(ip net.IP) (netip.Addr, error) {
	if addr, ok := netip.AddrFromSlice(ip); ok {
		return addr, nil
	}
	return netip.Addr{}, errors.New("Invalid IP")
}
