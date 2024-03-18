package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"testing"
)

func TestNetworkParsing(t *testing.T) {
	networkPrefix, err := netip.ParsePrefix("10.255.0.0/16")
	if err != nil {
		t.Fatal(err)
	}

	addr, err := netip.ParseAddr("10.255.0.1")
	if err != nil {
		t.Fatal(err)
	}

	prefix, err := addr.Prefix(networkPrefix.Bits())
	if err != nil {
		t.Fatal(err)
	}

	net.IPNet{
		IP:   addr,
		Mask: nil,
	}

	_, ipnet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", addr.String(), prefix.Bits()))
	if err != nil {
		t.Fatal(err)
	}

	log.Println(ipnet.String())
}
