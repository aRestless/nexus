package model

import (
	"database/sql"
	"database/sql/driver"
	"fmt"
	"gorm.io/gorm"
	"net/netip"
	"slices"
	"strings"
	"time"
)

type Client struct {
	gorm.Model
	HardwareAddress string
	PublicKeyHash   sql.NullString `gorm:"unique"`
	CommonName      string
	ClientNetworks  []ClientNetwork
}

type Prefix netip.Prefix

func (p *Prefix) Scan(value any) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot convert to string: %v", value)
	}

	prefix, err := netip.ParsePrefix(str)
	if err != nil {
		return fmt.Errorf("parsing prefix %s: %w", str, err)
	}

	*p = Prefix(prefix)
	return nil
}

func (p Prefix) Value() (driver.Value, error) {
	return netip.Prefix(p).String(), nil
}

func (p Prefix) ToNetip() netip.Prefix {
	return netip.Prefix(p)
}

type Prefixes []Prefix

func (p Prefixes) Value() (driver.Value, error) {
	var strs []string
	for _, prefix := range p {
		strs = append(strs, prefix.ToNetip().String())
	}

	slices.Sort(strs)

	return strings.Join(strs, ","), nil
}

func (p *Prefixes) Scan(value any) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot convert to string: %v", value)
	}

	strs := strings.Split(str, ",")

	var prefixes []Prefix
	for _, str := range strs {
		if str == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return fmt.Errorf("parsing prefix %s: %w", str, err)
		}
		prefixes = append(prefixes, Prefix(prefix))
	}

	*p = prefixes
	return nil
}

func (p Prefixes) ToNetip() []netip.Prefix {
	var result []netip.Prefix
	for _, prefix := range p {
		result = append(result, prefix.ToNetip())
	}

	return result
}

type Addr netip.Addr

func (a *Addr) Scan(value any) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot convert to string: %v", value)
	}

	addr, err := netip.ParseAddr(str)
	if err != nil {
		return fmt.Errorf("parsing address %s: %w", str, err)
	}

	*a = Addr(addr)
	return nil
}

func (a Addr) Value() (driver.Value, error) {
	return netip.Addr(a).String(), nil
}

func (a Addr) ToNetip() netip.Addr {
	return netip.Addr(a)
}

type AddrPort netip.AddrPort

func (a *AddrPort) Scan(value any) error {
	str, ok := value.(string)
	if !ok {
		return fmt.Errorf("cannot convert to string: %v", value)
	}

	addr, err := netip.ParseAddrPort(str)
	if err != nil {
		return fmt.Errorf("parsing address %s: %w", str, err)
	}

	*a = AddrPort(addr)
	return nil
}

func (a AddrPort) Value() (driver.Value, error) {
	return netip.AddrPort(a).String(), nil
}

func (a AddrPort) ToNetip() netip.AddrPort {
	return netip.AddrPort(a)
}

type Network struct {
	gorm.Model
	Name   string `gorm:"unique"`
	Prefix Prefix

	ClientNetworks []ClientNetwork
	NetworkGroups  []NetworkGroup
}

type Lighthouse struct {
	gorm.Model
	PublicAddr AddrPort
	NebulaIP   Addr

	NetworkID uint
	Network   Network
}

type Router struct {
	gorm.Model
	Subnet   Prefix
	NebulaIP Addr

	NetworkID uint
	Network   Network
}

type ClientNetwork struct {
	gorm.Model
	Address      Addr
	IsLighthouse bool
	Subnets      Prefixes

	ClientID uint
	Client   Client

	NetworkID uint
	Network   Network
	Groups    string
}

type NetworkGroup struct {
	gorm.Model
	Name string

	NetworkID uint
	Network   Network
}

type Certificate struct {
	gorm.Model
	Hash           string
	Groups         string
	Address        Addr
	NotAfter       time.Time
	RevokedAfter   time.Time
	RenewableAfter time.Time

	NetworkID uint
	Network   Network

	ClientID uint
	Client   Client
}

type Admin struct {
	gorm.Model
	Name          string
	PublicKeyHash sql.NullString `gorm:"unique"`
}

func (n *Network) FreeIP() (netip.Addr, error) {
	prefix := netip.Prefix(n.Prefix)
	next := prefix.Addr().Next()
	for !n.IsFree(next) {
		next = next.Next()

		if !prefix.Contains(next) {
			return netip.Addr{}, fmt.Errorf("ip network exhausted")
		}
	}

	return next, nil
}

func (n *Network) IsFree(ip netip.Addr) bool {
	for _, a := range n.ClientNetworks {
		addr := netip.Addr(a.Address)
		if addr.Compare(ip) == 0 {
			return false
		}
	}

	return true
}
