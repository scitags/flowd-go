// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "marker.bpf.h"

// Extract the lower 64 bits of an IPv6 address
static __always_inline __u64 ipv6AddrLo(struct in6_addr addr) {
	__u64 lo = bpf_htonl(addr.in6_u.u6_addr32[2]);
	return lo << 32 | bpf_htonl(addr.in6_u.u6_addr32[3]);
}

// Extract the upper 64 bits of an IPv6 address
static __always_inline __u64 ipv6AddrHi(struct in6_addr addr) {
	__u64 hi = bpf_htonl(addr.in6_u.u6_addr32[0]);
	return hi << 32 | bpf_htonl(addr.in6_u.u6_addr32[1]);
}

static __always_inline void populateFlowLbl(__u8 *flowLbl, __u32 flowTag) {
	flowLbl[0] = (flowTag & ( 0xF << 16)) >> 16;
	flowLbl[1] = (flowTag & (0xFF <<  8)) >>  8;
	flowLbl[2] =  flowTag &  0xFF;
}

static __always_inline void populateHbhHdr(struct hopByHopHdr_t *hbhHdr, __u8 nextHdr, __u32 flowTag) {
	// Set the extension header's next header.
	hbhHdr->nextHdr = nextHdr;

	// Check RFC 2460 Section 4.3: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.3
	// We need to specify the number of 8-octet units beyond the first 8 octets as the
	// header's length. In other words, the length of the extension header in bytes is:
	//   (8 * 8) + hdrLen * (8 * 8)
	hbhHdr->hdrLen = 0;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// We specify:
	//    00: skip the option if it's type is not recognized.
	//     0: option data doesn't change en-route.
	// 11111: option type.
	hbhHdr->opts[0] = 0x1F;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// The number of octets of the option's data.
	hbhHdr->opts[1] = 0x4;

	// Populate the option data with the flowTag.
	hbhHdr->opts[2] = 0x0 << 4 | (flowTag & ( 0xF << 16)) >> 16;
	hbhHdr->opts[3] =            (flowTag & (0xFF <<  8)) >>  8;
	hbhHdr->opts[4] =             flowTag &  0xFF;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// Add a Pad1 option to fill up the 8 octets we need at least.
	hbhHdr->opts[5] = 0x00;

	#ifdef GLOWD_DEBUG
		bpf_printk("flowd-go: Hop-by-Hop header nextHdr: %x", hbhHdr->nextHdr);
		bpf_printk("flowd-go: Hop-by-Hop header  hdrLen: %x", hbhHdr->hdrLen);
		bpf_printk("flowd-go: Hop-by-Hop header opts[0]: %x", hbhHdr->opts[0]);
		bpf_printk("flowd-go: Hop-by-Hop header opts[1]: %x", hbhHdr->opts[1]);
		bpf_printk("flowd-go: Hop-by-Hop header opts[2]: %x", hbhHdr->opts[2]);
		bpf_printk("flowd-go: Hop-by-Hop header opts[3]: %x", hbhHdr->opts[3]);
		bpf_printk("flowd-go: Hop-by-Hop header opts[4]: %x", hbhHdr->opts[4]);
		bpf_printk("flowd-go: Hop-by-Hop header opts[5]: %x", hbhHdr->opts[5]);
	#endif
}

static __always_inline void populateHbhDoHdr(struct hopByHopDestOptsHdr_t *hbhDoHdr, __u8 nextHdr, __u32 flowTag) {
	// Populate the embedded Hop-by-Hop Extension Header.
	populateHbhHdr(&(hbhDoHdr->hbhHdr), NEXT_HDR_DEST_OPTS, flowTag);

	// Set the extension header's next header.
	hbhDoHdr->nextHdr = nextHdr;

	// Check RFC 2460 Section 4.6: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.6
	// We need to specify the number of 8-octet units beyond the first 8 octets as the
	// header's length. In other words, the length of the extension header in bytes is:
	//   (8 * 8) + hdrLen * (8 * 8)
	hbhDoHdr->hdrLen = 0;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// We specify:
	//    00: skip the option if it's type is not recognized.
	//     0: option data doesn't change en-route.
	// 11111: option type.
	hbhDoHdr->opts[0] = 0x1F;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// The number of octets of the option's data.
	hbhDoHdr->opts[1] = 0x4;

	// Populate the option data with the flowTag.
	hbhDoHdr->opts[2] = 0x0 << 4 | (flowTag & ( 0xF << 16)) >> 16;
	hbhDoHdr->opts[3] =            (flowTag & (0xFF <<  8)) >>  8;
	hbhDoHdr->opts[4] =             flowTag &  0xFF;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// Add a Pad1 option to fill up the 8 octets we need at least.
	hbhDoHdr->opts[5] = 0x00;

	#ifdef GLOWD_DEBUG
		bpf_printk("flowd-go: Destination header nextHdr: %x", hbhDoHdr->nextHdr);
		bpf_printk("flowd-go: Destination header  hdrLen: %x", hbhDoHdr->hdrLen);
		bpf_printk("flowd-go: Destination header opts[0]: %x", hbhDoHdr->opts[0]);
		bpf_printk("flowd-go: Destination header opts[1]: %x", hbhDoHdr->opts[1]);
		bpf_printk("flowd-go: Destination header opts[2]: %x", hbhDoHdr->opts[2]);
		bpf_printk("flowd-go: Destination header opts[3]: %x", hbhDoHdr->opts[3]);
		bpf_printk("flowd-go: Destination header opts[4]: %x", hbhDoHdr->opts[4]);
		bpf_printk("flowd-go: Destination header opts[5]: %x", hbhDoHdr->opts[5]);
	#endif
}
