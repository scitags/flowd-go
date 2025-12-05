package stun

import (
	"testing"

	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

func TestHttp4(t *testing.T) {
	addrs4, _ := getDefaultAddrs(t)

	for _, addr := range addrs4 {
		t.Logf("requesting pubIP for IPv4 %s", addr.IP)
		pubIp, err := GetPubIPOverHTTP(Config{}, unix.AF_INET, addr.IP)
		if err != nil {
			t.Errorf("error getting public IPv4: %v", err)
			continue
		}
		t.Logf("          got public IPv4 %s", pubIp)
	}
}

func TestHttp6(t *testing.T) {
	_, addrs6 := getDefaultAddrs(t)

	for _, addr := range addrs6 {
		if types.IsIPLinkLocal(addr.IP) {
			continue
		}

		t.Logf("requesting pubIP for IPv6 %s", addr.IP)
		pubIp, err := GetPubIPOverHTTP(Config{}, unix.AF_INET6, addr.IP)
		if err != nil {
			t.Errorf("error getting public IPv6: %v", err)
			continue
		}
		t.Logf("          got public IPv6 %s", pubIp)
	}
}
