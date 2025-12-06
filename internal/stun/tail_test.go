package stun

import (
	"net/netip"
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

func getDefaultPrefixes(t *testing.T) ([]netip.Prefix, []netip.Prefix) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Fatalf("error getting the default interface: %v", err)
	}

	prefixes4, prefixes6, err := GetInterfacePrefixes(i)
	if err != nil {
		t.Fatalf("error getting interface addresses: %v", err)
	}

	return prefixes4, prefixes6
}

func TestStun4(t *testing.T) {
	prefixes4, _ := getDefaultPrefixes(t)

	for _, prefix := range prefixes4 {
		if types.IsIPLinkLocal(prefix.Addr()) {
			continue
		}

		t.Logf("requesting pubIP for IPv4 %s", prefix.Addr())
		pubIp, err := GetPubIPOverSTUN(stunConf, unix.AF_INET, prefix.Addr())
		if err != nil {
			t.Errorf("error getting public IPv4: %v", err)
			continue
		}
		t.Logf("          got public IPv4 %s", pubIp)
	}
}

func TestStun6(t *testing.T) {
	_, prefixes6 := getDefaultPrefixes(t)

	for _, prefix := range prefixes6 {
		if types.IsIPLinkLocal(prefix.Addr()) {
			continue
		}

		t.Logf("requesting pubIP for IPv6 %s", prefix.Addr())
		pubIp, err := GetPubIPOverSTUN(stunConf, unix.AF_INET6, prefix.Addr())
		if err != nil {
			t.Errorf("error getting public IPv6: %v", err)
			continue
		}
		t.Logf("          got public IPv6 %s", pubIp)
	}
}
