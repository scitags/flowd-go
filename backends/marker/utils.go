//go:build linux && ebpf

package marker

import (
	"fmt"
	"log/slog"
	"net/netip"
)

func extractHalves(ip netip.Addr) (uint64, uint64) {
	var addrHi uint64
	var addrLo uint64

	if !ip.Is6() {
		return 0, 0
	}

	s := ip.As16()
	for i := 0; i < 8; i++ {
		addrHi |= uint64(s[i]) << (8 * (8 - (1 + i)))
		addrLo |= uint64(s[i+8]) << (8 * (8 - (1 + i)))
	}

	return addrHi, addrLo
}

// Implementation of Section 1.2 of https://docs.google.com/document/d/1x9JsZ7iTj44Ta06IHdkwpv5Q2u4U2QGLWnUeN2Zf5ts/edit?usp=sharing
func (b *MarkerBackend) genFlowTag(experimentId, activityId uint32) uint32 {
	// If not using the flow label we can make do without any entropy bits and make our life
	// that much easier.
	if b.MarkingStrategy != Label {
		return experimentId<<8 | activityId&0xFF
	}

	// We'll slice this number up to get our needed 5 random bits
	rNum := b.rGen.Uint32()

	// The experimentId is supposed to be 9 bits long and reversed. That's why we have a hardcoded 9 here!
	var experimentIdRev uint32 = 0
	for i := 0; i < 9; i++ {
		experimentIdRev |= (experimentId & (0x1 << i) >> i) << ((9 - 1) - i)
	}

	var flowTag uint32 = (rNum & (0x3 << 18)) | ((experimentIdRev & 0x1FF) << 9) | (rNum & (0x1 << 8)) | ((activityId & 0x3F) << 2) | (rNum & 0x3)

	slog.Debug("genFlowTag", "experimentId", fmt.Sprintf("%b", experimentId), "experimentIdRev", fmt.Sprintf("%b", experimentIdRev),
		"activityId", fmt.Sprintf("%b", activityId), "flowTag", fmt.Sprintf("%b", flowTag))

	return flowTag
}
