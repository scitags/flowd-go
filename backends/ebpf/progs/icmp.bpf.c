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
			populateFlowLbl(l3->flow_lbl, *flowTag);
		#endif

		// Plundered from https://github.com/IurmanJ/ebpf-ipv6-exthdr-injection/blob/main/tc_ipv6_eh_kern.c
		#ifdef GLOWD_HBH_HEADER
			struct hopByHopHdr_t hopByHopHdr;

			// Initialise the header
			__builtin_memset(&hopByHopHdr, 0, sizeof(hopByHopHdr));

			// Fill in the Hob-by-Hop Header!
			populateHbhHdr(&hopByHopHdr, l3->nexthdr, *flowTag);

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopHdr_t), BPF_ADJ_ROOM_NET, 0)) {
				bpf_printk("flowd-go: error making room for the Hop-by-Hop header");
				return TC_ACT_SHOT;
			}

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hopByHopHdr, sizeof(struct hopByHopHdr_t), 0)) {
				bpf_printk("flowd-go: error making room for the Hop-by-Hop header");
				return TC_ACT_SHOT;
			}
		#endif

		#ifdef GLOWD_HBH_DO_HEADERS
			struct hopByHopDestOptsHdr_t hbhDestOptsHdrs;

			// Initialise the header
			__builtin_memset(&hbhDestOptsHdrs, 0, sizeof(hbhDestOptsHdrs));

			// Fill in the Hob-by-Hop and Destination Options Headers!
			populateHbhDoHdr(&hbhDestOptsHdrs, l3->nexthdr, *flowTag);

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopDestOptsHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopDestOptsHdr_t), BPF_ADJ_ROOM_NET, 0))
				return TC_ACT_SHOT;

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hbhDestOptsHdrs, sizeof(struct hopByHopDestOptsHdr_t), 0))
				return TC_ACT_SHOT;
		#endif

		return TC_ACT_OK;
	}

	// If we got here there's no flow defined...
	bpf_printk("flowd-go: found no entry in the map...");

	// Simply force the whole flow label to 1 so that we can
	// check the tag is altered when capturing traffic.
	populateFlowLbl(l3->flow_lbl, 0xFFFFF);

	return TC_ACT_OK;
}
