// +build ignore

/*
 * The authoritative reference is the Kernel documentation over at [0].
 * Be sure to check bpf-helpers(7) [1] too! This implementation is also
 * largely based on the example from libbpf-bootstrap [3]. Some great
 * documentation is also available over at [4]. Bear in mind this program
 * is of type BPF_PROG_TYPE_SCHED_CLS and we'll be running in the so called
 * direct action mode. What this implies togetehr with much more information
 * can be found on [5].
 * References:
 *   0: https://www.kernel.org/doc/html/latest/bpf/index.html
 *   1: https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
 *   3: https://github.com/libbpf/libbpf-bootstrap/blob/4a567f229efe8fc79ee1a2249569eb6b9c02ad1b/examples/c/tc.bpf.c
 *   4: https://docs.ebpf.io/linux/helper-function/
 *   5: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/
 */

// You'll need to install libbpf-devel (or the equivalent one) to get these headers!
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Include useful functions we defined ourselves. Note these must be
// included after the above so that all the necessary types are defined.
#include "utils.bpf.c"

// Include all the constants we've defined
#include "consts.h"

// The keys for our hash maps. Should we maybe combine the ports into a __u32?
struct fourTuple {
	__u64 ip6Hi;
	__u64 ip6Lo;
	__u16 dPort;
	__u16 sPort;
};

// Let's define our map. Note it'll be included in
// section .maps in the resulting binary.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, __u32);
} flowLabels SEC(".maps");

int handleICMP(struct ipv6hdr *l3) {
	bpf_printk("flowd-go: IPv6 source      address: %pI6", &l3->saddr);
	bpf_printk("flowd-go: IPv6 destination address: %pI6", &l3->daddr);

	__u64 ipv6SaddrLo = ipv6AddrLo(l3->saddr);
	__u64 ipv6SaddrHi = ipv6AddrHi(l3->saddr);

	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
	__u64 ipv6DaddrHi = ipv6AddrLo(l3->daddr);

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

		// Embed the configured flowTag into the IPv6 header.
		l3->flow_lbl[0] = (*flowTag & ( 0xF << 16)) >> 16;
		l3->flow_lbl[1] = (*flowTag & (0xFF <<  8)) >> 8;
		l3->flow_lbl[2] =  *flowTag &  0xFF;

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

int handleDatagram(struct __sk_buff *ctx, struct ipv6hdr *l3, void *data_end) {
	// If running in debug mode we'll handle ICMP messages as well
	// as TCP segments. That way we can leverage ping(8) to easily
	// generate traffic...
	#ifdef GLOWD_DEBUG
		if (l3->nexthdr == PROTO_IPV6_ICMP)
			return handleICMP(l3);
	#endif

	// We'll only handle TCP traffic flows
	if (l3->nexthdr == PROTO_TCP) {
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

	// Simply signal that the packet should proceed!
	return TC_ACT_OK;
}

// Let's hook the program on the TC! XDP will only look at the ingress traffic :(
// This macro simply configures the section where the following function will be
// inserted. When loading BPF programs, libbpf will look in sections tc and
// classifier for programs to actually load.
SEC("tc")

/*
 * The program will receive an __sk_buff which is a 'mirror' of the kernel's own
 * sk_buff [0]. This struct is very well documented over at [1].
 * References:
 *   0: https://docs.kernel.org/networking/skbuff.html
 *   1: https://docs.ebpf.io/linux/program-context/__sk_buff
 */
int marker(struct __sk_buff *ctx) {
	// Get a hold of the pointers to the start and end of the data so that we
	// can move around the payload.
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	// The pointer to the header of an Ethernet frame. As usual, struct ethhdr
	// is defined in vmlinux.h.
	struct ethhdr *l2;

	// The pointer to the header of a Dot1q frame. As usual, struct vlan_ethhdr
	// is defined on vmlinux.h. Bear in mind this struct defines both the MAC
	// addresses, the 802.1Q header and the EtherType field all together.
	struct vlan_ethhdr *l2Q;

	// The pointer to the header of an IPv6 datagram. As usual, struct ipv6hdr is
	// defined on vmlinux.h.
	struct ipv6hdr *l3;

	// Let's check whether the contents of the Ethernet frame are an IPv6 datagram.
	// We'll also need to be careful with the network's endianness, hence the call
	// to bpf_htons. This helper function is defined on libbpf's bpf_endian.h.

	// Let's check whether we got an Ethernet frame. If so, the encapsulated protocol
	// should be IPv6 (i.e. ETH_P_IPV6).
	if (ctx->protocol == bpf_htons(ETH_P_IPV6)) {
		#ifdef GLOWD_DEBUG
			// Check https://docs.ebpf.io/linux/helper-function/bpf_trace_printk/
			bpf_printk("flowd-go: got an Ethernet frame");
		#endif

		// Get a hold of the Ethernet frame header. We'll check we do indeed have more
		// information to read before going on. Otherwise the eBPF won't be accepted
		// by the kernel! This will be the case whenever we're making out way through
		// the payload defined by data and data_end, so we'll stop mentioning that...
		l2 = data;
		if ((void *)(l2 + 1) > data_end)
			return TC_ACT_OK;

		// Get a hold of the IPv6 header too!
		l3 = (void *)(l2 + 1);
		if ((void *)(l3 + 1) > data_end)
			return TC_ACT_OK;
	} else if (ctx->protocol == bpf_htons(ETH_P_8021Q)) {
		#ifdef GLOWD_DEBUG
			bpf_printk("flowd-go: got a 802.1Q frame");
		#endif

		// Get a hold of the 802.1Q header.
		l2Q = data;
		if ((void *)(l2Q + 1) > data_end)
			return TC_ACT_OK;

		// Is the encapsulated protocol IPv6?
		if (l2Q->h_vlan_encapsulated_proto != bpf_htons(ETH_P_IPV6))
			return TC_ACT_OK;

		// Get a hold of the IPv6 header too!
		l3 = (void *)(l2Q + 1);
		if ((void *)(l3 + 1) > data_end)
			return TC_ACT_OK;
	} else {
		// If we don't have an Ethernet or 802.1Q frame we'll just let the packet through.
		return TC_ACT_OK;
	}

	// If we made it here, we are dealing with an Ethernet or a 802.1Q frame and we have
	// already populated l3 so that it points to the IPv6 header. Let's process the
	// datagram and simply return whatever it determines.
	return handleDatagram(ctx, l3, data_end);
}

// Oh wow, the kernel refuses to load unlicensed stuff!
char LICENSE[] SEC("license") = "GPL";
