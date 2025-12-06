//go:build linux && ebpf

package marker

import (
	"net"
	"net/netip"
	"testing"
)

func extractHalvesOrig(ip net.IP) (uint64, uint64) {
	var addrHi uint64
	var addrLo uint64

	rawIP := []byte(ip)

	// net.IPs are internally represented as a 16-element []byte with
	// the last element being the LSByte and the first the MSByte.
	if len(rawIP) != 16 {
		return 0, 0
	}

	for i := 0; i < 8; i++ {
		addrHi |= uint64(rawIP[i]) << (8 * (8 - (1 + i)))
		addrLo |= uint64(rawIP[i+8]) << (8 * (8 - (1 + i)))
	}

	return addrHi, addrLo
}

func TestExtractHalves(t *testing.T) {
	for _, rawIP := range []string{"::1", "fe80::ec4:7aff:fe80:f104"} {
		hiOrig, loOrig := extractHalvesOrig(net.ParseIP(rawIP))
		t.Logf("hiOrig: %x, loOrig: %x", hiOrig, loOrig)

		hiNew, loNew := extractHalves(netip.MustParseAddr(rawIP))
		t.Logf("hiNew: %x, loNew: %x", hiNew, loNew)

		if hiOrig != hiNew || loOrig != loNew {
			t.Errorf("mismatching his and los: %x - %x; %x - %x", hiOrig, loOrig, hiNew, loNew)
		}
	}
}
