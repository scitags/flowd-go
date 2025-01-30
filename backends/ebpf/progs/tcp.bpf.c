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
		bpf_printk("flowd-go:      TCP source port: %d", bpf_htons(l4->source));
		bpf_printk("flowd-go: TCP destination port: %d", bpf_htons(l4->dest));
	#endif

	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
	__u64 ipv6DaddrHi = ipv6AddrHi(l3->daddr);

	// Declare the struct we'll use to index the map
	struct fourTuple flowHash;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&flowHash, 0, sizeof(flowHash));

	// Hardcode the port numbers we'll 'look for': there are none in ICMP!
	flowHash.ip6Hi = ipv6DaddrHi;
	flowHash.ip6Lo = ipv6DaddrLo;
	flowHash.dPort = bpf_htons(l4->dest);
	flowHash.sPort = bpf_htons(l4->source);

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);

	// If there's a flow configured, mark the packet
	if (flowTag) {
		#ifdef GLOWD_FLOW_LABEL

			#ifdef GLOWD_DEBUG
				bpf_printk("flowd-go: retrieved flowTag: %x", *flowTag);
			#endif

			populateFlowLbl(l3->flow_lbl, *flowTag);
		#endif

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
			l3->nexthdr = NEXT_HDR_DEST_OPTS;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct hopByHopDestOptsHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct hopByHopDestOptsHdr_t), BPF_ADJ_ROOM_NET, 0))
				return TC_ACT_SHOT;

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &hbhDestOptsHdrs, sizeof(struct hopByHopDestOptsHdr_t), 0))
				return TC_ACT_SHOT;
		#endif

		return TC_ACT_OK;
	}

	// We can also fall-through to the function's return statement, but
	// doing so here seems logically much clearer.
	return TC_ACT_OK;
}
