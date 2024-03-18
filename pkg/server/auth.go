package server

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/aRestless/nexus/pkg/types"
	"log"
	"net"
	"net/http"
	"time"
)

type ClientGetter interface {
	GetClient(id string) (*types.Client, error)
	GetClientByMAC(mac string) (*types.Client, error)
	GetClientByPublicKey(pubKeyHash string) (*types.Client, error)
}

type HardwareAddressAuthenticator struct {
	errorHandler func(err error, w http.ResponseWriter)
	localNetwork net.IPNet
}

func NewHardwareAddressAuthenticator(localNetwork net.IPNet, errorHandler func(err error, w http.ResponseWriter)) *HardwareAddressAuthenticator {
	haa := &HardwareAddressAuthenticator{
		errorHandler: func(error, http.ResponseWriter) {},
		localNetwork: localNetwork,
	}

	if errorHandler != nil {
		haa.errorHandler = errorHandler
	}

	return haa
}

func (a HardwareAddressAuthenticator) Middleware(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Hardware-Address")

		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			a.errorHandler(err, w)
			return
		}

		ip := net.ParseIP(host)
		mac, err := a.findMAC(ip)
		if err != nil {
			a.errorHandler(err, w)
			return
		}

		if mac != nil {
			r.Header.Add("X-Hardware-Address", mac.String())
		}

		log.Println(mac.String())

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

type PublicKeyAuthHeader struct {
	PublicKey []byte   `json:"k"`
	Challenge [40]byte `json:"c"`
	Nonce     [8]byte  `json:"n"`
	Signature []byte   `json:"s"`
}

type PublicKeyAuthenticator struct {
	salt         [32]byte
	challengeTTL time.Duration
	errorHandler func(err error, w http.ResponseWriter)
}

func NewPublicKeyAuthenticator(salt [32]byte, errorHandler func(err error, w http.ResponseWriter)) *PublicKeyAuthenticator {
	pka := &PublicKeyAuthenticator{
		errorHandler: func(error, http.ResponseWriter) {},
		salt:         salt,
		challengeTTL: 5 * time.Minute,
	}

	if errorHandler != nil {
		pka.errorHandler = errorHandler
	}

	return pka
}

func (a PublicKeyAuthenticator) Middleware(h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		r.Header.Del("X-Public-Key-Hash")
		r.Header.Del("X-Common-Name")

		var c *x509.Certificate
		if r.TLS != nil {
			c = r.TLS.PeerCertificates[0]
		} else {
			sslCert := r.Header.Get("X-SSL-CERT")
			block, _ := pem.Decode([]byte(sslCert))
			var err error
			c, err = x509.ParseCertificate(block.Bytes)
			if err != nil {
				a.errorHandler(err, w)
				return
			}
		}

		b, err := x509.MarshalPKIXPublicKey(c.PublicKey)
		if err != nil {
			a.errorHandler(err, w)
			return
		}

		r.Header.Add("X-Common-Name", c.Subject.CommonName)

		hash := sha256.Sum256(b)
		r.Header.Add("X-Public-Key-Hash", hex.EncodeToString(hash[:]))

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}
