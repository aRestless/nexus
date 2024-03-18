package server

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"

	"github.com/aRestless/nexus/pkg/model"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

type Server struct {
	address string
	db      *gorm.DB
	ca      *CA
	tls     *TLS
}

type CA struct {
	key   []byte
	curve cert.Curve
	cert  *cert.NebulaCertificate
}

type TLS struct {
	keyPath  string
	certPath string
}

func NewTLS(keyPath, certPath string) *TLS {
	return &TLS{
		keyPath:  keyPath,
		certPath: certPath,
	}
}

func New(options ...func(*Server)) *Server {
	svr := &Server{
		address: "127.0.0.1:3000",
	}
	for _, o := range options {
		o(svr)
	}

	return svr
}

func (s *Server) Serve() error {
	r, err := s.router()
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	return http.ListenAndServe(s.address, r)
}

func (s *Server) ServeTLS() error {
	r, err := s.router()
	if err != nil {
		return fmt.Errorf("creating router: %w", err)
	}

	srv := http.Server{
		Addr:    s.address,
		Handler: r,
		TLSConfig: &tls.Config{
			ClientAuth: tls.RequireAnyClientCert,
		},
	}

	return srv.ListenAndServeTLS(s.tls.certPath, s.tls.keyPath)
}

func (s *Server) router() (chi.Router, error) {
	r := chi.NewRouter()

	var localNetwork net.IPNet = net.IPNet{}
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		panic(err)
	}

	hwaa := NewHardwareAddressAuthenticator(localNetwork, s.handleErr)
	pka := NewPublicKeyAuthenticator([32]byte(salt), s.handleErr)

	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(hwaa.Middleware)
	r.Use(pka.Middleware)

	r.Get("/whoami", s.whoami)

	r.Post("/clients", s.createOrUpdateClient)
	r.Get("/clients", s.listClients)
	r.Delete("/clients/{publicKeyHash}", s.deleteClient)
	r.Get("/clients/{publicKeyHash}/networks", s.listClientNetworks)
	r.Get("/clients/{publicKeyHash}/networks/{network}", s.getClientNetwork)
	r.Get("/clients/{publicKeyHash}/networks/{network}/ca", s.getClientNetworkCA)
	r.Get("/clients/{publicKeyHash}/networks/{network}/certificates", s.listCertificates)
	r.Get("/clients/{publicKeyHash}/networks/{network}/certificates/{hash}", s.getCertificate)
	r.Post("/clients/{publicKeyHash}/networks/{network}/certificates", s.createCertificate)
	r.Get("/clients/{publicKeyHash}/networks/{network}/lighthouses", s.listLighthouses)
	r.Post("/clients/{publicKeyHash}/networks/{network}/lighthouses", s.createLighthouse)
	r.Get("/clients/{publicKeyHash}/networks/{network}/revocations", s.listRevocations)
	r.Get("/clients/{publicKeyHash}/networks/{network}/routers", s.listRouters)
	r.Post("/clients/{publicKeyHash}/networks/{network}/routers", s.createRouter)

	r.Get("/networks", s.listNetworks)
	r.Post("/networks", s.createNetwork)
	r.Get("/networks/{network}/clients", s.listNetworkClients)
	r.Post("/networks/{network}/clients", s.createNetworkClient)
	r.Put("/networks/{network}/clients/{publicKeyHash}", s.updateNetworkClient)
	r.Delete("/networks/{network}/clients/{publicKeyHash}", s.deleteNetworkClient)
	return r, nil
}

func (s *Server) authenticateClient(r *http.Request, adminOnly bool) *model.Client {
	publicKeyHash := r.Header.Get("X-Public-Key-Hash")
	macAddress := r.Header.Get("X-Hardware-Address")
	commonName := r.Header.Get("X-Common-Name")

	if publicKeyHash != chi.URLParam(r, "publicKeyHash") || adminOnly {
		if s.authenticateAdmin(r) {
			return s.findClientByPublicKey(chi.URLParam(r, "publicKeyHash"))
		}

		return nil
	}

	client, _, _ := s.findOrCreateClient(publicKeyHash, macAddress, commonName)

	return client
}

func (s *Server) authenticateAdmin(r *http.Request) bool {
	publicKeyHash := r.Header.Get("X-Public-Key-Hash")

	result := s.db.First(&model.Admin{}, "public_key_hash = ?", publicKeyHash)

	return result.RowsAffected > 0
}

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) {
	publicKeyHash := r.Header.Get("X-Public-Key-Hash")

	resp := WhoamiResponse{PublicKeyHash: publicKeyHash}

	b, err := json.Marshal(&resp)
	if err != nil {
		s.handleErr(err, w)
		return
	}

	_, err = w.Write(b)
	if err != nil {
		s.handleErr(err, w)
		return
	}
}

func (s *Server) handleErr(err error, w http.ResponseWriter) {
	log.Println(err)
	w.WriteHeader(500)
}

func (s *Server) handleResponse(w http.ResponseWriter, status int, response interface{}) error {
	b, err := json.Marshal(response)
	if err != nil {
		return fmt.Errorf("marshalling response: %w", err)
	}

	w.WriteHeader(status)
	_, err = w.Write(b)
	if err != nil {
		fmt.Errorf("flushing response: %w", err)
	}

	return nil
}
