// +build ignore

// When calling function we'll just let the compiler know we **really** want it to 'inline' the functions.
// Technicalities aside, this boils down to 'copy-pasting' the function's body wherever the function is
// called. Given the usual workflow in eBPF programs this actually makes a lot of sense! We're also declaring
// the function as 'static' to avoid having the compiler generate an equivalent non-inline version of the
// function so that other translation units can links against it. In other words, we simply ask the compiler
// to just focus on the inline-version of the function. Be sure to check the following for more info:
//   0: https://stackoverflow.com/questions/21835664/why-declare-a-c-function-as-static-inline
//   1: https://en.wikipedia.org/wiki/Inline_function
//   2: https://docs.ebpf.io/ebpf-library/libbpf/ebpf/__always_inline/
static __always_inline int handleICMP(struct __sk_buff *ctx, struct ipv6hdr *l3) {
	bpf_printk("flowd-go: IPv6 source      address: %pI6", &l3->saddr);
	bpf_printk("flowd-go: IPv6 destination address: %pI6", &l3->daddr);

	__u64 ipv6SaddrLo = ipv6AddrLo(l3->saddr);
	__u64 ipv6SaddrHi = ipv6AddrHi(l3->saddr);

	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
	__u64 ipv6DaddrHi = ipv6AddrHi(l3->daddr);

	bpf_printk("flowd-go: IPv6 saddr (hi --- lo): %x --- %x", ipv6SaddrHi, ipv6SaddrLo);
	bpf_printk("flowd-go: IPv6 daddr (hi --- lo): %x --- %x", ipv6DaddrHi, ipv6DaddrLo);

	bpf_printk("flowd-go: IPv6 flow label: %x --- %x --- %x",
		(__u8)l3->flow_lbl[0], (__u8)l3->flow_lbl[1], (__u8)l3->flow_lbl[2]);

	// Declare the struct we'll use to index the map
	struct fourTuple flowHash;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&flowHash, 0, sizeof(flowHash));

	// Hardcode the port numbers we'll 'look for': there are none in ICMP!
	flowHash.ip6Hi = ipv6DaddrHi;
	flowHash.ip6Lo = ipv6DaddrLo;
	flowHash.dPort = 5777;
	flowHash.sPort = 2345;

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);

	// If ther's a flow defined (i.e. flowTag != NULL)
	if (flowTag) {
		bpf_printk("flowd-go: retrieved flowTag: %u", *flowTag);

		#ifdef GLOWD_FLOW_LABEL
			// Embed the configured flowTag into the IPv6 header.
			l3->flow_lbl[0] = (*flowTag & ( 0xF << 16)) >> 16;
			l3->flow_lbl[1] = (*flowTag & (0xFF <<  8)) >> 8;
			l3->flow_lbl[2] =  *flowTag &  0xFF;
		#endif

		// Plundered from https://github.com/IurmanJ/ebpf-ipv6-exthdr-injection/blob/main/tc_ipv6_eh_kern.c
		#ifdef GLOWD_EXT_HEADERS
			struct hopByHopHdr_t hopByHopHdr;
			__builtin_memset(&hopByHopHdr, 0, sizeof(hopByHopHdr));

			hopByHopHdr.nextHdr = l3->nexthdr;
			hopByHopHdr.hdrLen = 0;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// We specify:
			//    00: skip the option if it's type is not recognized.
			//     0: option data doesn't change en-route.
			// 11111: option type.
			hopByHopHdr.opts[0] = 0x1F;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// The number of octets of the option's data.
			hopByHopHdr.opts[1] = 0x4;

			// Populate the option data with the flowTag.
			hopByHopHdr.opts[2] = 0x0 << 4 | (*flowTag & ( 0xF << 16)) >> 16;
			hopByHopHdr.opts[3] = (*flowTag & (0xFF <<  8)) >> 8;
			hopByHopHdr.opts[4] = *flowTag &  0xFF;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// Add a Pad1 option to fill up the 8 octets we need at least.
			hopByHopHdr.opts[5] = 0x00;

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopHdr_t));

			bpf_printk("flowd-go: Hop-by-Hop header nextHdr: %x", hopByHopHdr.nextHdr);
			bpf_printk("flowd-go: Hop-by-Hop header hdrLen: %x", hopByHopHdr.hdrLen);
			bpf_printk("flowd-go: Hop-by-Hop header opts[0]: %x", hopByHopHdr.opts[0]);
			bpf_printk("flowd-go: Hop-by-Hop header opts[1]: %x", hopByHopHdr.opts[1]);
			bpf_printk("flowd-go: Hop-by-Hop header opts[2]: %x", hopByHopHdr.opts[2]);
			bpf_printk("flowd-go: Hop-by-Hop header opts[3]: %x", hopByHopHdr.opts[3]);
			bpf_printk("flowd-go: Hop-by-Hop header opts[4]: %x", hopByHopHdr.opts[4]);
			bpf_printk("flowd-go: Hop-by-Hop header opts[5]: %x", hopByHopHdr.opts[5]);
			bpf_printk("flowd-go:       IPv6 header nexthdr: %x", l3->nexthdr);

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopHdr_t), BPF_ADJ_ROOM_NET, 0)) {
				bpf_printk("flowd-go: error making room for the Hop-by-Hop header");
				return TC_ACT_OK;
				// return TC_ACT_SHOT;
			}

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hopByHopHdr, sizeof(struct hopByHopHdr_t), 0)) {
				bpf_printk("flowd-go: error making room for the Hop-by-Hop header");
				return TC_ACT_OK;
				// return TC_ACT_SHOT;
			}

			// Check https://github.com/xdp-project/bpf-examples/blob/master/nat64-bpf/nat64_kern.c for an example on how to fix
			// mangled checksums. This shouldn't really be needed on IPv6 AFAIK given how upper layer (i.e. L4) protocols leverage
			// a pseudo-header for computing checksums as seen on RFC 2460 Section 8.1: https://www.rfc-editor.org/rfc/rfc2460.html#section-8.1
			// if (bpf_l4_csum_replace(ctx, ...)) {
			// 	bpf_printk("flowd-go: error recomputing the L4 checksum");
			// 	return TC_ACT_OK;
			// 	// return TC_ACT_SHOT;
			// }
		#endif

		return TC_ACT_OK;
	}

	// If we got here there's no flow defined...
	bpf_printk("flowd-go: found no entry in the map...");

	// Simply force the whole flow label to 1 so that we can
	// check the tag is altered when capturing traffic.
	l3->flow_lbl[2] = 0xFF;
	l3->flow_lbl[1] = 0xFF;
	l3->flow_lbl[0] =  0xF;

	return TC_ACT_OK;
}
