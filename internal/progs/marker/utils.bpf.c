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

static __always_inline void populateExtensionHdr(struct extensionHdr_t *extHdr, __u8 nextHdr, __u32 flowTag) {
	// Set the extension header's next header.
	extHdr->nextHdr = nextHdr;

	// Check RFC 2460 Section 4.3: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.3
	// We need to specify the number of 8-octet units beyond the first 8 octets as the
	// header's length. In other words, the length of the extension header in bytes is:
	//   (8 * 8) + hdrLen * (8 * 8)
	extHdr->hdrLen = 0;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// We specify:
	//    00: skip the option if it's type is not recognized.
	//     0: option data doesn't change en-route.
	// 11110: experimental option type. See RFC 4727: https://www.rfc-editor.org/rfc/rfc4727.html
	// Check the IANA IPv6 assignments too at https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
	extHdr->opts[0] = 0x1E;

	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	// The number of octets of the option's data.
	extHdr->opts[1] = 0x3;

	// Populate the option data with the flowTag.
	extHdr->opts[2] = 0x0 << 4 | (flowTag & ( 0xF << 16)) >> 16;
	extHdr->opts[3] =            (flowTag & (0xFF <<  8)) >>  8;
	extHdr->opts[4] =             flowTag &  0xFF;

	// Add a Pad1 option to fill up the 8 octets we need at least.
	// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
	extHdr->opts[5] = 0x00;

	#ifdef FLOWD_DEBUG
		bpf_printk("flowd-go: extensionHeader nextHdr: %d", extHdr->nextHdr);
		bpf_printk("flowd-go: extensionHeader  hdrLen: %x", extHdr->hdrLen);
		bpf_printk("flowd-go: extensionHeader opts[0]: %x", extHdr->opts[0]);
		bpf_printk("flowd-go: extensionHeader opts[1]: %x", extHdr->opts[1]);
		bpf_printk("flowd-go: extensionHeader opts[2]: %x", extHdr->opts[2]);
		bpf_printk("flowd-go: extensionHeader opts[3]: %x", extHdr->opts[3]);
		bpf_printk("flowd-go: extensionHeader opts[4]: %x", extHdr->opts[4]);
		bpf_printk("flowd-go: extensionHeader opts[5]: %x", extHdr->opts[5]);
	#endif
}

static __always_inline void populateCompExtensionHdr(struct compExtensionHdr_t *compHdr, __u8 nextHdr, __u32 flowTag) {
	// Populate the embedded Hop-by-Hop Extension Header.
	populateExtensionHdr(&(compHdr->hopByHopHdr), NEXT_HDR_DEST_OPTS, flowTag);

	// Populate the embedded Destination Options Extension Header.
	populateExtensionHdr(&(compHdr->destOptsHdr), nextHdr, flowTag);

	#ifdef FLOWD_DEBUG
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.nextHdr: %d", compHdr->hopByHopHdr.nextHdr);
		bpf_printk("flowd-go: compExtensionHeader  hopByHopHdr.hdrLen: %x", compHdr->hopByHopHdr.hdrLen);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[0]: %x", compHdr->hopByHopHdr.opts[0]);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[1]: %x", compHdr->hopByHopHdr.opts[1]);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[2]: %x", compHdr->hopByHopHdr.opts[2]);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[3]: %x", compHdr->hopByHopHdr.opts[3]);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[4]: %x", compHdr->hopByHopHdr.opts[4]);
		bpf_printk("flowd-go: compExtensionHeader hopByHopHdr.opts[5]: %x", compHdr->hopByHopHdr.opts[5]);

		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.nextHdr: %d", compHdr->destOptsHdr.nextHdr);
		bpf_printk("flowd-go: compExtensionHeader   destOptHdr.hdrLen: %x", compHdr->destOptsHdr.hdrLen);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[0]: %x", compHdr->destOptsHdr.opts[0]);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[1]: %x", compHdr->destOptsHdr.opts[1]);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[2]: %x", compHdr->destOptsHdr.opts[2]);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[3]: %x", compHdr->destOptsHdr.opts[3]);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[4]: %x", compHdr->destOptsHdr.opts[4]);
		bpf_printk("flowd-go: compExtensionHeader  destOptHdr.opts[5]: %x", compHdr->destOptsHdr.opts[5]);
	#endif
}
