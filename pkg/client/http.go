package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/aRestless/nexus/pkg/server"
	"github.com/sirupsen/logrus"
)

type Client struct {
	c   *http.Client
	id  string
	mu  sync.Mutex
	url string
	l   *logrus.Logger
}

var ErrorNotFound = errors.New("not found")
var ErrorUnauthorized = errors.New("unauthorized")
var ErrorForbidden = errors.New("forbidden")
var ErrorServerError = errors.New("server error")
var ErrorBadRequest = errors.New("bad request")

func New(serverUrl string, clientCertPath, clientKeyPath string, insecureSkipVerify bool, l *logrus.Logger) (*Client, error) {
	clientTLSCert, err := tls.LoadX509KeyPair(clientCertPath, clientKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load TLS client certificate: %w", err)
	}

	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("load cert pool: %w", err)
	}

	tlsConfig := &tls.Config{
		RootCAs:            certPool,
		Certificates:       []tls.Certificate{clientTLSCert},
		InsecureSkipVerify: insecureSkipVerify,
	}

	tr := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Client{
		c:   &http.Client{Transport: tr},
		url: serverUrl,
		l:   l,
	}, nil
}

func (c *Client) ListClients() (server.ListClientsResponse, error) {
	url := fmt.Sprintf("%s/clients", c.url)
	var response server.ListClientsResponse
	err := c.get(url, &response)
	if err != nil {
		return server.ListClientsResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) DeleteClient(client string) (server.DeleteClientResponse, error) {
	url := fmt.Sprintf("%s/clients/%s", c.url, client)
	var response server.DeleteClientResponse
	err := c.delete(url, &response)
	if err != nil {
		return server.DeleteClientResponse{}, fmt.Errorf("delete: %w", err)
	}

	return response, nil
}

func (c *Client) ListNetworks() (server.ListNetworksResponse, error) {
	url := fmt.Sprintf("%s/networks", c.url)
	var response server.ListNetworksResponse
	err := c.get(url, &response)
	if err != nil {
		return server.ListNetworksResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) CreateNetwork(req server.CreateNetworkRequest) (server.CreateNetworkResponse, error) {
	url := fmt.Sprintf("%s/networks", c.url)
	var response server.CreateNetworkResponse
	err := c.post(url, &req, &response)
	if err != nil {
		return server.CreateNetworkResponse{}, fmt.Errorf("post: %w", err)
	}

	return response, nil
}

func (c *Client) CreateNetworkClient(network string, req server.CreateNetworkClientRequest) (server.CreateNetworkClientResponse, error) {
	url := fmt.Sprintf("%s/networks/%s/clients", c.url, network)
	var response server.CreateNetworkClientResponse
	err := c.post(url, &req, &response)
	if err != nil {
		return server.CreateNetworkClientResponse{}, fmt.Errorf("post: %w", err)
	}

	return response, nil
}

func (c *Client) DeleteNetworkClient(network string, client string) (server.DeleteNetworkClientResponse, error) {
	url := fmt.Sprintf("%s/networks/%s/clients/%s", c.url, network, client)
	var response server.DeleteNetworkClientResponse
	err := c.delete(url, &response)
	if err != nil {
		return server.DeleteNetworkClientResponse{}, fmt.Errorf("post: %w", err)
	}

	return response, nil
}

func (c *Client) UpdateNetworkClient(network string, publicKeyHash string, req server.UpdateNetworkClientRequest) (server.UpdateNetworkClientResponse, error) {
	url := fmt.Sprintf("%s/networks/%s/clients/%s", c.url, network, publicKeyHash)
	var response server.UpdateNetworkClientResponse
	err := c.put(url, &req, &response)
	if err != nil {
		return server.UpdateNetworkClientResponse{}, fmt.Errorf("post: %w", err)
	}

	return response, nil
}

func (c *Client) ListNetworkClients(network string) (server.ListClientNetworksResponse, error) {
	url := fmt.Sprintf("%s/networks/%s/clients", c.url, network)
	var response server.ListClientNetworksResponse
	err := c.get(url, &response)
	if err != nil {
		return server.ListClientNetworksResponse{}, fmt.Errorf("post: %w", err)
	}

	return response, nil
}

func (c *Client) ListClientNetworkCertificates(network string) (server.ListCertificatesResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.ListCertificatesResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/certificates", c.url, clientID, network)

	var response server.ListCertificatesResponse
	err = c.get(url, &response)
	if err != nil {
		return server.ListCertificatesResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) GetClientNetworkCertificate(network, certHash string) (server.GetCertificateResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.GetCertificateResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/certificates/%s", c.url, clientID, network, certHash)

	var response server.GetCertificateResponse
	err = c.get(url, &response)
	if err != nil {
		return server.GetCertificateResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) CreateClientNetworkCertificate(network string, request server.CreateCertificateRequest) (server.CreateCertificateResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.CreateCertificateResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/certificates", c.url, clientID, network)

	var response server.CreateCertificateResponse
	err = c.post(url, &request, &response)
	if err != nil {
		return server.CreateCertificateResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}
func (c *Client) ListClientNetworkRevocations(network string) (server.ListRevocationsResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.ListRevocationsResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/revocations", c.url, clientID, network)

	var response server.ListRevocationsResponse
	err = c.get(url, &response)
	if err != nil {
		return server.ListRevocationsResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}
func (c *Client) ListClientNetworkLighthouses(network string) (server.ListLighthousesResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.ListLighthousesResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/lighthouses", c.url, clientID, network)

	var response server.ListLighthousesResponse
	err = c.get(url, &response)
	if err != nil {
		return server.ListLighthousesResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) CreateClientNetworkLighthouse(network string, request server.CreateLighthouseRequest) (server.CreateLighthouseResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.CreateLighthouseResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/lighthouses", c.url, clientID, network)

	var response server.CreateLighthouseResponse
	err = c.post(url, &request, &response)
	if err != nil {
		return server.CreateLighthouseResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) ListClientNetworkRouters(network string) (server.ListRoutersResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.ListRoutersResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/routers", c.url, clientID, network)

	var response server.ListRoutersResponse
	err = c.get(url, &response)
	if err != nil {
		return server.ListRoutersResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) CreateClientNetworkRouter(network string, request server.CreateRouterRequest) (server.CreateRouterResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.CreateRouterResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/routers", c.url, clientID, network)

	var response server.CreateRouterResponse
	err = c.post(url, &request, &response)
	if err != nil {
		return server.CreateRouterResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) GetClientNetwork(network string) (server.ClientNetworkResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.ClientNetworkResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s", c.url, clientID, network)

	var response server.ClientNetworkResponse
	err = c.get(url, &response)
	if err != nil {
		return server.ClientNetworkResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) GetClientNetworkCA(network string) (server.GetCAResponse, error) {
	clientID, err := c.GetClientID()
	if err != nil {
		return server.GetCAResponse{}, fmt.Errorf("get client id: %w", err)
	}

	url := fmt.Sprintf("%s/clients/%s/networks/%s/ca", c.url, clientID, network)

	var response server.GetCAResponse
	err = c.get(url, &response)
	if err != nil {
		return server.GetCAResponse{}, fmt.Errorf("get: %w", err)
	}

	return response, nil
}

func (c *Client) GetClientID() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.id != "" {
		return c.id, nil
	}

	url := fmt.Sprintf("%s/whoami", c.url)

	var response server.WhoamiResponse
	err := c.get(url, &response)
	if err != nil {
		return "", fmt.Errorf("get /whoami: %w", err)
	}

	c.id = response.PublicKeyHash
	c.l.Debugf("Set ClientID to %s\n", c.id)
	return c.id, nil
}

func (c *Client) get(url string, target any) error {
	resp, err := c.c.Get(url)
	if err != nil {
		return fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()

	c.l.Debugf("%d GET %s", resp.StatusCode, url)
	if err = errorFromStatusCode(resp.StatusCode); err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(target)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	return nil
}

func (c *Client) post(url string, payload any, response any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	resp, err := c.c.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()

	c.l.Debugf("%d POST %s", resp.StatusCode, url)
	if err = errorFromStatusCode(resp.StatusCode); err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	return nil
}

func (c *Client) put(url string, payload any, response any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest("PUT", url, bytes.NewReader(b))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := c.c.Do(req)
	if err != nil {
		return fmt.Errorf("get %s: %w", url, err)
	}
	defer resp.Body.Close()

	c.l.Debugf("%d POST %s", resp.StatusCode, url)
	if err = errorFromStatusCode(resp.StatusCode); err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	return nil
}

func (c *Client) delete(url string, response any) error {
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")

	resp, err := c.c.Do(req)
	if err != nil {
		return fmt.Errorf("delete %s: %w", url, err)
	}
	defer resp.Body.Close()

	c.l.Debugf("%d DELETE %s", resp.StatusCode, url)
	if err = errorFromStatusCode(resp.StatusCode); err != nil {
		return err
	}

	err = json.NewDecoder(resp.Body).Decode(response)
	if err != nil {
		return fmt.Errorf("decode body: %w", err)
	}

	return nil
}

func errorFromStatusCode(code int) error {
	switch code {
	case http.StatusNotFound:
		return ErrorNotFound
	case http.StatusUnauthorized:
		return ErrorUnauthorized
	case http.StatusForbidden:
		return ErrorForbidden
	case http.StatusBadRequest:
		return ErrorBadRequest
	}

	if code/100 == 5 {
		return ErrorServerError
	}

	if code/100 == 2 {
		return nil
	}

	return fmt.Errorf("unexpected status code %d", code)
}
