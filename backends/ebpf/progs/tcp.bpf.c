// +build ignore

static __always_inline int handleTCP(struct __sk_buff *ctx, struct ipv6hdr *l3, void *data_end) {
	// The pointer to the header of an TCP segment. As usual, struct tcphdr is
	// defined on vmlinux.h.
	struct tcphdr *l4;

	// Get a hold of the TCP header!
	l4 = (void *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		return TC_ACT_OK;

	#ifdef GLOWD_DEBUG
		bpf_printk("flowd-go:      TCP source port: %x", bpf_htons(l4->source));
		bpf_printk("flowd-go: TCP destination port: %x", bpf_htons(l4->dest));
	#endif

	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
	__u64 ipv6DaddrHi = ipv6AddrLo(l3->daddr);

	// Declare the struct we'll use to index the map
	struct fourTuple flowHash;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&flowHash, 0, sizeof(flowHash));

	// Hardcode the port numbers we'll 'look for': there are none in ICMP!
	flowHash.ip6Hi = ipv6DaddrHi;
	flowHash.ip6Lo = ipv6DaddrLo;
	flowHash.dPort = l4->dest;
	flowHash.sPort = l4->source;

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);

	// If there's a flow configured, mark the packet
	if (flowTag) {
		#ifdef GLOWD_FLOW_LABEL
			l3->flow_lbl[0] = (*flowTag & ( 0xF << 16)) >> 16;
			l3->flow_lbl[1] = (*flowTag & (0xFF <<  8)) >>  8;
			l3->flow_lbl[2] =  *flowTag &  0xFF;
		#endif

		#ifdef GLOWD_HBH_HEADER
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
			hopByHopHdr.opts[3] =            (*flowTag & (0xFF <<  8)) >>  8;
			hopByHopHdr.opts[4] =             *flowTag &  0xFF;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// Add a Pad1 option to fill up the 8 octets we need at least.
			hopByHopHdr.opts[5] = 0x00;

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopHdr_t), BPF_ADJ_ROOM_NET, 0))
				return TC_ACT_SHOT;

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hopByHopHdr, sizeof(struct hopByHopHdr_t), 0))
				return TC_ACT_SHOT;
		#endif

		#ifdef GLOWD_HBH_DO_HEADERS
			struct hopByHopAndDestOptsHdr_t hbhDestOptsHdrs;
			__builtin_memset(&hbhDestOptsHdrs, 0, sizeof(hbhDestOptsHdrs));

			hbhDestOptsHdrs.destNextHdr = l3->nexthdr;
			hbhDestOptsHdrs.destHdrLen = 0;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// We specify:
			//    00: skip the option if it's type is not recognized.
			//     0: option data doesn't change en-route.
			// 11111: option type.
			hbhDestOptsHdrs.optsDest[0] = hbhDestOptsHdrs.optsHbH[0] = 0x1F;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// The number of octets of the option's data.
			hbhDestOptsHdrs.optsDest[1] = hbhDestOptsHdrs.optsHbH[1] = 0x4;

			// Populate the option data with the flowTag.
			hbhDestOptsHdrs.optsDest[2] = hbhDestOptsHdrs.optsHbH[2] = 0x0 << 4 | (*flowTag & ( 0xF << 16)) >> 16;
			hbhDestOptsHdrs.optsDest[3] = hbhDestOptsHdrs.optsHbH[3] =            (*flowTag & (0xFF <<  8)) >>  8;
			hbhDestOptsHdrs.optsDest[4] = hbhDestOptsHdrs.optsHbH[4] =             *flowTag &  0xFF;

			// Check RFC 2460 Section 4.2: https://www.rfc-editor.org/rfc/rfc2460.html#section-4.2
			// Add a Pad1 option to fill up the 8 octets we need at least.
			hbhDestOptsHdrs.optsDest[5] = hbhDestOptsHdrs.optsHbH[5] = 0x00;

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;
			hbhDestOptsHdrs.hbhNextHdr = NEXT_HDR_DEST_OPTS;
			hbhDestOptsHdrs.hbhHdrLen = 0;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopAndDestOptsHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopAndDestOptsHdr_t), BPF_ADJ_ROOM_NET, 0))
				return TC_ACT_SHOT;

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hbhDestOptsHdrs, sizeof(struct hopByHopAndDestOptsHdr_t), 0))
				return TC_ACT_SHOT;
		#endif

		return TC_ACT_OK;
	}

	// We can also fall-through to the function's return statement, but
	// doing so here seems logically much clearer.
	return TC_ACT_OK;
}
