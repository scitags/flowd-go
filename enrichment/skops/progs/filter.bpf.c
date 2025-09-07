#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "sk_ops.bpf.h"

static __always_inline int handleDatagram(struct __sk_buff *ctx, struct ipv6hdr *l3, void *data_end) {
	// If running in debug mode we'll handle ICMP messages as well
	// as TCP segments. That way we can leverage ping(8) to easily
	// generate traffic...
	#ifdef GLOWD_DEBUG
		if (l3->nexthdr == PROTO_IPV6_ICMP)
			return handleICMP(ctx, l3);
	#endif

	// We'll only handle TCP traffic flows
	if (l3->nexthdr == PROTO_TCP) {
		return handleTCP(ctx, l3, data_end);
	}

	// Simply signal that the packet should proceed!
	return TC_ACT_OK;

	flowHash.ip6Hi = ipv6DaddrHi;
	flowHash.ip6Lo = ipv6DaddrLo;
	flowHash.dPort = bpf_htons(l4->dest);
	flowHash.sPort = bpf_htons(l4->source);

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);
}

static __always_inline void handleClosingConnection() {
	// Declare the struct we'll use to index the map
	struct fourTuple flowHash;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&flowHash, 0, sizeof(flowHash));

	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
	__u64 ipv6DaddrHi = ipv6AddrHi(l3->daddr);
	flowHash.ip6Hi = ipv6DaddrHi;
	flowHash.ip6Lo = ipv6DaddrLo;
	flowHash.dPort = bpf_htons(l4->dest);
	flowHash.sPort = bpf_htons(l4->source);

	key = 1, value = 5678;
	result = bpf_map_update_elem(&my_map, &key, &value, BPF_NOEXIST);
}
