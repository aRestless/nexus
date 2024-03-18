package server

import (
	"net/netip"
	"time"
)

type CreateClientRequest struct {
}

type ListClientsResponse struct {
	Items []GetClientResponse `json:"items"`
}

type GetClientResponse struct {
	PublicKeyHash   string   `json:"publicKeyHash"`
	CommonName      string   `json:"commonName"`
	HardwareAddress string   `json:"hardwareAddress,omitempty"`
	Networks        []string `json:"networks"`
}

type CreateClientResponse GetClientResponse
type DeleteClientResponse GetClientResponse

type CreateNetworkRequest struct {
	Name    string       `json:"name"`
	Network netip.Prefix `json:"network"`
}

type GetClientNetworkResponse struct {
	PublicKeyHash string         `json:"publicKeyHash"`
	Address       *netip.Addr    `json:"address"`
	Groups        []string       `json:"groups"`
	Subnets       []netip.Prefix `json:"subnets"`
	IsLighthouse  bool           `json:"isLighthouse"`
}

type ListClientNetworksResponse struct {
	Items []GetClientNetworkResponse `json:"items"`
}

type CreateNetworkClientRequest struct {
	PublicKeyHash string         `json:"publicKeyHash"`
	Address       *netip.Addr    `json:"address"`
	Groups        []string       `json:"groups"`
	Subnets       []netip.Prefix `json:"subnets"`
	IsLighthouse  bool           `json:"isLighthouse"`
}

type UpdateNetworkClientRequest struct {
	Address      *netip.Addr    `json:"address"`
	Groups       []string       `json:"groups"`
	Subnets      []netip.Prefix `json:"subnets"`
	IsLighthouse bool           `json:"isLighthouse"`
}

type ClientNetworkResponse struct {
	PublicKeyHash string      `json:"publicKeyHash"`
	Address       *netip.Addr `json:"address"`
	Groups        []string    `json:"groups"`
}

type CreateNetworkClientResponse struct {
	Network      string         `json:"network"`
	Address      netip.Addr     `json:"address"`
	Groups       []string       `json:"groups"`
	IsLighthouse bool           `json:"isLighthouse"`
	Subnets      []netip.Prefix `json:"subnets"`
}

type UpdateNetworkClientResponse CreateNetworkClientResponse
type DeleteNetworkClientResponse CreateNetworkClientResponse

type ListClientNetworkResponse struct {
	Items []ClientNetworkResponse `json:"items"`
}

type CreateCertificateRequest struct {
	PubPEM []byte `json:"pubPem"`
}

type CreateCertificateResponse struct {
	GetCertificateResponse
	PEM []byte `json:"pem"`
}

type ListCertificatesResponse struct {
	Items []GetCertificateResponse `json:"items"`
}
type GetCertificateResponse struct {
	Address        netip.Addr `json:"address"`
	Hash           string     `json:"hash"`
	Groups         []string   `json:"groups"`
	NotAfter       time.Time  `json:"notAfter"`
	RevokedAfter   time.Time  `json:"revokedAfter"`
	RenewableAfter time.Time  `json:"renewableAfter"`
}

type Revocation struct {
	Hash string
}
type ListRevocationsResponse struct {
	Items []Revocation
}

type ListLighthousesResponse struct {
	Items []Lighthouse
}

type CreateLighthouseRequest struct {
	PublicAddr netip.AddrPort
}

type CreateLighthouseResponse Lighthouse

type Lighthouse struct {
	PublicAddr netip.AddrPort
	NebulaIP   netip.Addr
}

type ListRoutersResponse struct {
	Items []Router `json:"items"`
}

type CreateRouterRequest struct {
	Subnet netip.Prefix
}

type CreateRouterResponse Router

type Router struct {
	NebulaIP netip.Addr
	Subnet   netip.Prefix
}

type WhoamiResponse struct {
	PublicKeyHash string `json:"publicKeyHash"`
}

type GetCAResponse struct {
	PEM []byte `json:"pem"`
}

type GetNetworkResponse struct {
	Name   string       `json:"name"`
	Prefix netip.Prefix `json:"prefix"`
	Groups []string     `json:"groups"`
}

type CreateNetworkResponse GetNetworkResponse

type ListNetworksResponse struct {
	Items []GetNetworkResponse `json:"items"`
}
