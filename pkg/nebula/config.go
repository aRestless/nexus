package nebula

import "net/netip"

type AddedConfig struct {
	PKI           PKI                             `yaml:"pki"`
	StaticHostMap map[netip.Addr][]netip.AddrPort `yaml:"static_host_map"`
	Lighthouse    Lighthouse                      `yaml:"lighthouse"`
	Tun           Tun                             `yaml:"tun"`
}

type PKI struct {
	CA                string   `yaml:"ca"`
	Cert              string   `yaml:"cert"`
	Blocklist         []string `yaml:"blocklist"`
	DisconnectInvalid bool     `yaml:"disconnect_invalid"`
}

type Lighthouse struct {
	Hosts []netip.Addr `yaml:"hosts"`
}

type Tun struct {
	Dev          string        `yaml:"dev"`
	UnsafeRoutes []UnsafeRoute `yaml:"unsafe_routes"`
}

type UnsafeRoute struct {
	Route   string `json:"route"`
	Via     string `json:"via"`
	Metric  int    `json:"metric"`
	MTU     int    `json:"mtu"`
	Install bool   `json:"install"`
}
