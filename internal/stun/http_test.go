package stun

import (
	"testing"

	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

func TestHttp4(t *testing.T) {
	prefixes4, _ := getDefaultPrefixes(t)

	for _, prefix := range prefixes4 {
		t.Logf("requesting pubIP for IPv4 %s", prefix.Addr())
		pubIp, err := GetPubIPOverHTTP(Config{}, unix.AF_INET, prefix.Addr())
		if err != nil {
			t.Errorf("error getting public IPv4: %v", err)
			continue
		}
		t.Logf("          got public IPv4 %s", pubIp)
	}
}

func TestHttp6(t *testing.T) {
	_, prefixes6 := getDefaultPrefixes(t)

	for _, prefix := range prefixes6 {
		if types.IsIPLinkLocal(prefix.Addr()) {
			continue
		}

		t.Logf("requesting pubIP for IPv6 %s", prefix.Addr())
		pubIp, err := GetPubIPOverHTTP(Config{}, unix.AF_INET6, prefix.Addr())
		if err != nil {
			t.Errorf("error getting public IPv6: %v", err)
			continue
		}
		t.Logf("          got public IPv6 %s", pubIp)
	}
}
