package stun

import (
	"net"
	"testing"

	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

var stunConf = Config{
	StunServers: []string{
		"stun.l.google.com:3478",
		"stun1.l.google.com:3478",
		"stun2.l.google.com:3478",
		"stun3.l.google.com:3478",
		"stun4.l.google.com:3478",
	},
}

func getDefaultAddrs(t *testing.T) ([]*net.IPNet, []*net.IPNet) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Fatalf("error getting the default interface: %v", err)
	}

	addrs4, addrs6, err := GetInterfaceAddresses(i)
	if err != nil {
		t.Fatalf("error getting interface addresses: %v", err)
	}

	return addrs4, addrs6
}

func TestStun4(t *testing.T) {
	addrs4, _ := getDefaultAddrs(t)

	for _, addr := range addrs4 {
		if types.IsIPLinkLocal(addr.IP) {
			continue
		}

		t.Logf("requesting pubIP for IPv4 %s", addr.IP)
		pubIp, err := GetPubIPOverSTUN(stunConf, unix.AF_INET, addr.IP)
		if err != nil {
			t.Errorf("error getting public IPv4: %v", err)
			continue
		}
		t.Logf("          got public IPv4 %s", pubIp)
	}
}

func TestStun6(t *testing.T) {
	_, addrs6 := getDefaultAddrs(t)

	for _, addr := range addrs6 {
		if types.IsIPLinkLocal(addr.IP) {
			continue
		}

		t.Logf("requesting pubIP for IPv6 %s", addr.IP)
		pubIp, err := GetPubIPOverSTUN(stunConf, unix.AF_INET6, addr.IP)
		if err != nil {
			t.Errorf("error getting public IPv6: %v", err)
			continue
		}
		t.Logf("          got public IPv6 %s", pubIp)
	}
}
