package server

import (
	"github.com/j-keck/arping"
	"net"
)

func (a HardwareAddressAuthenticator) findMAC(ip net.IP) (net.HardwareAddr, error) {
	if !a.localNetwork.Contains(ip) {
		return nil, nil
	}

	addr, _, err := arping.Ping(ip)
	return addr, err
}
