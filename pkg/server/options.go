package server

import (
	"github.com/slackhq/nebula/cert"
	"gorm.io/gorm"
)

func WithAddress(address string) func(*Server) {
	return func(s *Server) {
		s.address = address
	}
}

func WithDatabase(db *gorm.DB) func(*Server) {
	return func(s *Server) {
		s.db = db
	}
}

func WithTLS(tls *TLS) func(*Server) {
	return func(s *Server) {
		s.tls = tls
	}
}

func WithCA(key []byte, curve cert.Curve, cert *cert.NebulaCertificate) func(*Server) {
	return func(s *Server) {
		s.ca = &CA{
			key:   key,
			curve: curve,
			cert:  cert,
		}
	}
}
