package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/netip"
	"os"
	"time"

	"github.com/aRestless/nexus/pkg/client"
	"github.com/aRestless/nexus/pkg/nebula"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/util"
	"github.com/spf13/cobra"
)

func initNebulaCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use: "nebula",
		Run: nebulaRun,
	}

	cmd.PersistentFlags().String("tls.key", "cert/client.key.pem", "")
	cmd.PersistentFlags().String("tls.cert", "cert/client.cert.pem", "")
	cmd.PersistentFlags().Bool("tls.insecureSkipVerify", false, "")
	cmd.PersistentFlags().String("tls.name", "", "")
	cmd.MarkPersistentFlagRequired("tls.name")

	cmd.Flags().StringArray("pull-routes", []string{}, "")
	cmd.Flags().StringArray("push-routes", []string{}, "")

	cmd.Flags().String("config", "", "Path to the directory including the nebula config")
	cmd.MarkFlagRequired("config")

	cmd.Flags().String("network", "", "The network to connect to")
	cmd.MarkFlagRequired("network")

	cmd.Flags().String("server", "", "Nexus server URL")
	cmd.MarkFlagRequired("server")

	cmd.Flags().String("lighthouse.addr", "", "The address under which to advertise this client as lighthouse.")

	return cmd
}

func nebulaRun(cmd *cobra.Command, args []string) {
	configPath, err := cmd.Flags().GetString("config")
	if err != nil {
		log.Fatalf("getting config flag: %v", err)
	}

	network, err := cmd.Flags().GetString("network")
	if err != nil {
		log.Fatalf("getting network flag: %v", err)
	}

	server, err := cmd.Flags().GetString("server")
	if err != nil {
		log.Fatalf("getting server flag: %v", err)
	}

	clientKeyPath, err := cmd.Flags().GetString("tls.key")
	if err != nil {
		log.Fatalf("getting tls.key flag: %v", err)
	}

	clientCertPath, err := cmd.Flags().GetString("tls.cert")
	if err != nil {
		log.Fatalf("getting tls.key flag: %v", err)
	}

	insecureSkipVerify, err := cmd.Flags().GetBool("tls.insecureSkipVerify")
	if err != nil {
		log.Fatalf("getting tls.insecureSkipVerify flag: %v", err)
	}

	commonName, err := cmd.Flags().GetString("tls.name")
	if err != nil {
		log.Fatalf("getting tls.name flag: %v", err)
	}

	pullRouteStrings, err := cmd.Flags().GetStringArray("pull-routes")
	if err != nil {
		log.Fatalf("getting --pull-routes flag: %v", err)
	}

	var pullRoutes []netip.Prefix
	for _, str := range pullRouteStrings {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			log.Fatalf("parse route %s: %v", str, err)
		}

		pullRoutes = append(pullRoutes, prefix)
	}

	pushRouteStrings, err := cmd.Flags().GetStringArray("push-routes")
	if err != nil {
		log.Fatalf("getting --push-routes flag: %v", err)
	}

	var pushRoutes []netip.Prefix
	for _, str := range pushRouteStrings {
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			log.Fatalf("parse route %s: %v", str, err)
		}

		pushRoutes = append(pushRoutes, prefix)
	}

	lighthouseAddrPortStr, err := cmd.Flags().GetString("lighthouse.addr")
	if err != nil {
		log.Fatalf("getting --lighthouse.addr flag: %v", err)
	}
	var lighthouseAddrPort netip.AddrPort
	if lighthouseAddrPortStr != "" {
		lighthouseAddrPort, err = netip.ParseAddrPort(lighthouseAddrPortStr)
		if err != nil {
			log.Fatalf("parse lighthouse.addr %s: %v", lighthouseAddrPortStr, err)
		}
	}

	mustCreateTLSCertificate(commonName, clientCertPath, clientKeyPath)

	l := logrus.New()
	l.Out = os.Stdout
	l.Level = logrus.DebugLevel

	fileInfo, err := os.Stat(configPath)
	if err != nil {
		log.Fatalf("failed to stat config at %s: %v", configPath, err)
	}

	if !fileInfo.IsDir() {
		log.Fatalf("config path %s is not a directory", configPath)
	}

	cl, err := client.New(server, clientCertPath, clientKeyPath, insecureSkipVerify, l)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to create HTTP client", err, l)
	}

	ctrl, err := nebula.Main(cl, configPath, network, lighthouseAddrPort, pullRoutes, pushRoutes, l)
	if err != nil {
		util.LogWithContextIfNeeded("Failed to start", err, l)
		os.Exit(1)
	}

	ctrl.Start()
	notifyReady(l)
	ctrl.ShutdownBlock()

	os.Exit(0)
}

func mustCreateTLSCertificate(commonName, clientCertPath, clientKeyPath string) {
	if _, err := os.Stat(clientKeyPath); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			panic(fmt.Errorf("file stat for %s: %w", clientKeyPath, err))
		}

		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			panic(fmt.Errorf("generate RSA key: %w", err))
		}

		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		// PEM encoding of private key
		keyPEM := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: keyBytes,
			},
		)

		err = os.WriteFile(clientKeyPath, keyPEM, 0600)
		if err != nil {
			panic(fmt.Errorf("write key file %s: %w", clientKeyPath, err))
		}
	}

	creationNeeded, err := tlsCertCreationNeeded(commonName, clientCertPath)
	if err != nil {
		log.Fatalf("TLS cert creation needed: %v", err)
	}

	if !creationNeeded {
		return
	}

	keyPEM, err := os.ReadFile(clientKeyPath)
	if err != nil {
		panic(fmt.Errorf("read key file %s: %w", clientKeyPath, err))
	}

	block, _ := pem.Decode(keyPEM)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			panic(fmt.Errorf("parse private key: %w", err))
		}

		key = privKey.(*rsa.PrivateKey)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(30 * 365 * 24 * time.Hour)
	template := x509.Certificate{
		SerialNumber:          big.NewInt(0),
		Subject:               pkix.Name{CommonName: commonName},
		SignatureAlgorithm:    x509.SHA256WithRSA,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyAgreement | x509.KeyUsageKeyEncipherment | x509.KeyUsageDataEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(fmt.Errorf("create certificate: %w", err))
	}

	certPem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: derBytes,
		},
	)

	err = os.WriteFile(clientCertPath, certPem, 0600)
	if err != nil {
		panic(fmt.Errorf("write certificate file %s: %w", clientCertPath, err))
	}
}

func tlsCertCreationNeeded(commonName, clientCertPath string) (bool, error) {
	b, err := os.ReadFile(clientCertPath)
	if os.IsNotExist(err) {
		return true, nil
	}

	if err != nil {
		return false, fmt.Errorf("read file %s: %w", clientCertPath, err)
	}

	block, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("parse certificate: %w", err)
	}

	return c.Subject.CommonName != commonName, nil
}
