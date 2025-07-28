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

// You'll need to install libbpf-devel (or the equivalent one on non-RHEL systems) to get these headers!
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

// Include all the constants and types we've defined
#include "marker.bpf.h"

// Include useful functions we defined ourselves. Note these must be
// included after the above so that all the necessary types are defined.
#include "utils.bpf.c"
#include "icmp.bpf.c"
#include "tcp.bpf.c"

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
