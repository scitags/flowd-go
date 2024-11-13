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
		l3->flow_lbl[0] = (*flowTag & ( 0xF << 16)) >> 16;
		l3->flow_lbl[1] = (*flowTag & (0xFF <<  8)) >> 8;
		l3->flow_lbl[2] =  *flowTag &  0xFF;
	}

	// We can also fall-through to the function's return statement, but
	// doing so here seems logically much clearer.
	return TC_ACT_OK;
}
