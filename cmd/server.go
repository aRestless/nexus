package cmd

import (
	"crypto/rand"
	"fmt"
	"github.com/aRestless/nexus/pkg/model"
	"github.com/aRestless/nexus/pkg/server"
	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cert"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ed25519"
	"log"
	"os"
	"time"
)

func serve(cmd *cobra.Command, args []string) {
	l := logrus.New()
	l.Level = logrus.DebugLevel

	dbPath, err := cmd.Flags().GetString("db.path")
	if err != nil {
		log.Fatalf("getting --db.path flag: %v", err)
	}

	admins, err := cmd.Flags().GetStringToString("admins")
	if err != nil {
		log.Fatalf("getting --admins flag: %v", err)
	}

	db, err := model.NewDatabase(dbPath, admins)
	if err != nil {
		log.Fatalf("create database: %v", err)
	}

	isTLS, err := cmd.Flags().GetBool("tls")
	if err != nil {
		log.Fatalf("getting --tls flag: %v", err)
	}

	caKeyPath, err := cmd.Flags().GetString("ca.key")
	if err != nil {
		log.Fatalf("getting --ca.key flag: %v", err)
	}

	caKeyBytes, err := getCAKey(caKeyPath)
	if err != nil {
		log.Fatalf("getting ca key: %v", err)
	}

	caKey, _, curve, err := cert.UnmarshalSigningPrivateKey(caKeyBytes)
	if err != nil {
		log.Fatalf("unmarshalling ca key: %v", err)
	}

	caCertPath, err := cmd.Flags().GetString("ca.cert")
	if err != nil {
		log.Fatalf("getting --ca.cert flag: %v", err)
	}

	caCertBytes, err := getCACert(caCertPath, caKey, curve)
	if err != nil {
		log.Fatalf("reading ca cert: %v", err)
	}

	caCert, _, err := cert.UnmarshalNebulaCertificateFromPEM(caCertBytes)
	if err != nil {
		log.Fatalf("unmarshalling ca cert: %v", err)
	}

	addr, err := cmd.Flags().GetString("addr")
	if err != nil {
		log.Fatalf("getting --addr flag: %v", err)
	}

	opts := []func(*server.Server){
		server.WithDatabase(db),
		server.WithCA(caKey, curve, caCert),
	}

	if addr != "" {
		opts = append(opts, server.WithAddress(addr))
	}

	if isTLS {
		keyPath, err := cmd.Flags().GetString("tls.key")
		if err != nil {
			log.Fatalf("getting --tls.key flag: %v", err)
		}
		certPath, err := cmd.Flags().GetString("tls.cert")
		if err != nil {
			log.Fatalf("getting --tls.cert flag: %v", err)
		}
		opts = append(opts, server.WithTLS(server.NewTLS(keyPath, certPath)))
		s := server.New(opts...)
		log.Fatal(s.ServeTLS())
	} else {
		s := server.New(opts...)
		log.Fatal(s.Serve())
	}
}

func getCAKey(caKeyPath string) ([]byte, error) {
	b, err := os.ReadFile(caKeyPath)
	if os.IsNotExist(err) {
		return createCAKey(caKeyPath)
	}

	if err != nil {
		return nil, fmt.Errorf("read ca key file: %w", err)
	}

	return b, nil
}

func createCAKey(caKeyPath string) ([]byte, error) {
	curve := cert.Curve_CURVE25519
	_, rawPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 keys: %s", err)
	}

	b := cert.MarshalSigningPrivateKey(curve, rawPriv)
	err = os.WriteFile(caKeyPath, b, 0600)
	if err != nil {
		return nil, fmt.Errorf("write private key: %w", err)
	}

	return b, err
}

func getCACert(caCertPath string, privKey []byte, curve cert.Curve) ([]byte, error) {
	b, err := os.ReadFile(caCertPath)
	if os.IsNotExist(err) {
		return createCACert(caCertPath, privKey, curve)
	}

	if err != nil {
		return nil, fmt.Errorf("read ca cert file: %w", err)
	}

	return b, nil
}

func createCACert(caCertPath string, privKey []byte, curve cert.Curve) ([]byte, error) {
	if curve != cert.Curve_CURVE25519 {
		return nil, fmt.Errorf("unsupported curve %s", curve)
	}

	pubKey := make([]byte, ed25519.PublicKeySize)
	copy(pubKey, privKey[32:])

	nc := cert.NebulaCertificate{
		Details: cert.NebulaCertificateDetails{
			Name:      "nexus",
			Groups:    nil,
			Ips:       nil,
			Subnets:   nil,
			NotBefore: time.Now(),
			NotAfter:  time.Now().AddDate(30, 0, 0),
			PublicKey: pubKey,
			IsCA:      true,
			Curve:     curve,
		},
	}

	err := nc.Sign(curve, privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal ca cert: %w", err)
	}

	b, err := nc.MarshalToPEM()
	if err != nil {
		return nil, fmt.Errorf("marshal cert to PEM: %w", err)
	}

	err = os.WriteFile(caCertPath, b, 0600)
	if err != nil {
		return nil, fmt.Errorf("write ca cert: %w", err)
	}

	return b, nil
}
