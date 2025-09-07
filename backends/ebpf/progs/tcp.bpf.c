// +build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "marker.bpf.h"

static __always_inline int handleTCP(struct __sk_buff *ctx, struct ipv6hdr *l3, void *data_end) {
	// The pointer to the header of an TCP segment. As usual, struct tcphdr is
	// defined on vmlinux.h.
	struct tcphdr *l4;

	// Get a hold of the TCP header!
	l4 = (void *)(l3 + 1);
	if ((void *)(l4 + 1) > data_end)
		return TC_ACT_OK;

	#ifdef FLOWD_DEBUG
		bpf_printk("flowd-go:      TCP source port: %d", bpf_htons(l4->source));
		bpf_printk("flowd-go: TCP destination port: %d", bpf_htons(l4->dest));
	#endif

	// Declare the struct we'll use to index the map
	struct fourTuple flowHash;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&flowHash, 0, sizeof(flowHash));

	#ifndef FLOWD_MATCH_ALL
		// Populate the lookup based on the incoming datagram's data
		flowHash.ip6Hi = ipv6AddrHi(l3->daddr);
		flowHash.ip6Lo = ipv6AddrLo(l3->daddr);
		flowHash.dPort = bpf_htons(l4->dest);
		flowHash.sPort = bpf_htons(l4->source);
	#endif

	#ifdef FLOWD_DEBUG
		bpf_printk("flowd-go: IPv6                 destination address: %pI6", &l3->daddr);
		bpf_printk("flowd-go:     IPv6 destination address Hi [127:64]: %x", flowHash.ip6Hi);
		bpf_printk("flowd-go:     IPv6 destination address Lo   [63:0]: %x", flowHash.ip6Lo);
		bpf_printk("flowd-go: TCP                     destination port: %d", flowHash.dPort);
		bpf_printk("flowd-go: TCP                          source port: %d", flowHash.sPort);
	#endif

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);

	// If there's a flow configured, mark the packet
	if (flowTag) {
		#if defined(FLOWD_LABEL) || defined(FLOWD_MATCH_ALL)

			#ifdef FLOWD_DEBUG
				bpf_printk("flowd-go: retrieved flowTag: %x", *flowTag);
			#endif

			populateFlowLbl(l3->flow_lbl, *flowTag);
		#endif

		#if defined(FLOWD_HBH) || defined(FLOWD_DO)
			struct extensionHdr_t extensionHdr;

			// Check we won't go overboard and overwhelm the MTU!
			// In order to check individual GSO/GRO segments in an sk_buff use the
			// BPF_MTU_CHK_SEGS as seen on 0:
			//   0: see https://github.com/xdp-project/bpf-examples/blob/main/MTU-tests/tc_mtu_enforce.c
			__u32 mtuLen = 0;
			if(bpf_check_mtu(ctx, 0, &mtuLen, sizeof(extensionHdr), 0)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: adding extension headers would overflow the MTU, skipping...");
				#endif

				return TC_ACT_OK;
			}

			#ifdef FLOWD_DEBUG
				bpf_printk("flowd-go: IPv6 header size increase: %d bytes", sizeof(extensionHdr));
				bpf_printk("flowd-go: detected MTU: %d bytes", mtuLen);
			#endif

			// Initialise the header
			__builtin_memset(&extensionHdr, 0, sizeof(extensionHdr));

			// Fill in the Hob-by-Hop Header!
			populateExtensionHdr(&extensionHdr, l3->nexthdr, *flowTag);

			#ifdef FLOWD_HBH
				// Signal the next header is a Hop-by-Hop Extension Header
				l3->nexthdr = NEXT_HDR_HOP_BY_HOP;
			#else
				// Signal the next header is a Destination Options Extension Header
				l3->nexthdr = NEXT_HDR_DEST_OPTS;
			#endif

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct extensionHdr_t));

			// Be sure to check available flags (i.e. BPF_F_ADJ_ROOM_*) on bpf-helpers(7).
			if (bpf_skb_adjust_room(ctx, sizeof(struct extensionHdr_t), BPF_ADJ_ROOM_NET, 0)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: error making room for the extension header");
				#endif

				return TC_ACT_SHOT;
			}

			// Be sure to check available flags (i.e. BPF_F_{RECOMPUTE_CSUM,NVALIDATE_HASH}) on bpf-helpers(7).
			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &extensionHdr, sizeof(struct extensionHdr_t), BPF_F_RECOMPUTE_CSUM)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: error storing the extension header");
				#endif

				return TC_ACT_SHOT;
			}
		#endif

		#ifdef FLOWD_HBHDO
			struct compExtensionHdr_t compExtensionHdr;

			__u32 mtuLen = 0;
			if(bpf_check_mtu(ctx, 0, &mtuLen, sizeof(compExtensionHdr), 0)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: adding extension headers would overflow the MTU, skipping...");
				#endif

				return TC_ACT_OK;
			}

			#ifdef FLOWD_DEBUG
				bpf_printk("flowd-go: IPv6 header size increase: %d bytes", sizeof(compExtensionHdr));
				bpf_printk("flowd-go: detected MTU: %d bytes", mtuLen);
			#endif

			// Initialise the header
			__builtin_memset(&compExtensionHdr, 0, sizeof(compExtensionHdr));

			// Fill in the Hob-by-Hop and Destination Options Headers!
			populateCompExtensionHdr(&compExtensionHdr, l3->nexthdr, *flowTag);

			// Signal the next header is a Hop-by-Hop extension header
			l3->nexthdr = NEXT_HDR_HOP_BY_HOP;

			// Update the payload length
			l3->payload_len = bpf_htons(bpf_ntohs(l3->payload_len) + sizeof(struct compExtensionHdr_t));

			if (bpf_skb_adjust_room(ctx, sizeof(struct compExtensionHdr_t), BPF_ADJ_ROOM_NET, 0)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: error making room for the extension header");
				#endif

				return TC_ACT_SHOT;
			}

			if (bpf_skb_store_bytes(ctx, sizeof(struct ethhdr) + sizeof(struct ipv6hdr), &compExtensionHdr, sizeof(struct compExtensionHdr_t), BPF_F_RECOMPUTE_CSUM)) {
				#ifdef FLOWD_DEBUG
					bpf_printk("flowd-go: error storing the extension header");
				#endif

				return TC_ACT_SHOT;
			}
		#endif

		return TC_ACT_OK;
	}

	// We can also fall-through to the function's return statement, but
	// doing so here seems logically much clearer.
	return TC_ACT_OK;
}
