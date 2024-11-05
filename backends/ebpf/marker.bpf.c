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

// Enforceable actions. These are defined on include/uapi/linux/if_ether.h
// (i.e. /usr/include/linux/pkt_cls.h). The problem is including linux/pkt_cls.h
// conflicts with the inclusion of vmlinux.h!
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0

// The ETH_P_* constants are defined in include/uapi/linux/if_ether.h
// (i.e. /usr/include/linux/if_ether.h). Again, their inclusion conflicts
// with vmlinux.h...
#define ETH_P_IP    0x0800 /* Internet Protocol packet */
#define ETH_P_IPV6  0x86DD /* IPv6 over bluebook */
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header */

// Protocol numbers. Check https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define PROTO_IP_ICMP   0x01
#define PROTO_TCP       0x06
#define PROTO_UDP       0x11
#define PROTO_IPV6_ICMP 0x3A

// The keys for our hash maps. Should we maybe combine the ports into a __u32?
struct fourTuple {
	__u64 ip6Hi;
	__u64 ip6Lo;
	__u16 dPort;
	__u16 sPort;
};

// Let's define our map!
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, __u32);
} flowLabels SEC(".maps");

// long ringBufferFlags = 0;

// Let's hook the program on the TC! XDP will only look at the ingress traffic :(
// This macro simply configures the section where the following will be inserted.
// When loading BPF programs, libbpf will look in sections tc and classifier for
// programs. to actually load.
SEC("tc")

/*
 * The program will receive an __sk_buff which is a 'mirror' of the kernel's own
 * sk_buff [0]. This struct is very well documented over at [1].
 * References:
 *   0: https://docs.kernel.org/networking/skbuff.html
 *   1: https://docs.ebpf.io/linux/program-context/__sk_buff
*/
int marker(struct __sk_buff *ctx) {
	void *data_end = (void *)(__u64)ctx->data_end;
	void *data = (void *)(__u64)ctx->data;

	// Check vmlinux.h for the definitions of these structs!
	// Also, the struct for 802.1Q seems to be vlan_ethhdr!
	// We just need to consider it on top of ETH_P_IPV6 basically.
	struct ethhdr *l2;
	struct ipv6hdr *l3;
	struct tcphdr *l4;

	// Let's check whether the contents of the Ethernet frame are an IPv6 datagram.
	// We'll also need to be careful with the network's endianness, hence the call
	// to bpf_htons. This helper function is defined on libbpf's bpf_endian.h.
	if (ctx->protocol != bpf_htons(ETH_P_IPV6))
		return TC_ACT_OK;

	// Check https://docs.ebpf.io/linux/helper-function/bpf_trace_printk/
	// bpf_printk("hello from glowd's eBPF backend: we got an IPv6 datagram!");

	// Get a hold of the Ethernet frame header. We'll check we do indeed have more
	// information to read before going on.
	l2 = data;
	if ((void *)(l2 + 1) > data_end)
		return TC_ACT_OK;

	// Get a hold of the IPv6 header and check we do have some payload!
	l3 = (void *)(l2 + 1);
	if ((void *)(l3 + 1) > data_end)
		return TC_ACT_OK;

	__u64 ipv6SaddrLo = bpf_htonl(l3->saddr.in6_u.u6_addr32[2]);
	ipv6SaddrLo = ipv6SaddrLo << 32 | bpf_htonl(l3->saddr.in6_u.u6_addr32[3]);

	__u64 ipv6SaddrHi = bpf_htonl(l3->saddr.in6_u.u6_addr32[0]);
	ipv6SaddrHi = ipv6SaddrHi << 32 | bpf_htonl(l3->saddr.in6_u.u6_addr32[1]);

	__u64 ipv6DaddrLo = bpf_htonl(l3->daddr.in6_u.u6_addr32[2]);
	ipv6DaddrLo = ipv6DaddrLo << 32 | bpf_htonl(l3->daddr.in6_u.u6_addr32[3]);

	__u64 ipv6DaddrHi = bpf_htonl(l3->daddr.in6_u.u6_addr32[0]);
	ipv6DaddrHi = ipv6DaddrHi << 32 | bpf_htonl(l3->daddr.in6_u.u6_addr32[1]);

	__u8 flowLblLo = l3->flow_lbl[2];
	__u8 flowLblMi = l3->flow_lbl[1];
	__u8 flowLblHi = l3->flow_lbl[0];

	if (l3->nexthdr == PROTO_IPV6_ICMP) {
		#ifdef GLOWD_DEBUG
			bpf_printk("   IPv6 saddr: %pI6", &l3->saddr);
			bpf_printk("   IPv6 daddr: %pI6", &l3->daddr);

			bpf_printk("   IPv6 saddr (hi --- lo): %x --- %x", ipv6SaddrHi, ipv6SaddrLo);
			bpf_printk("   IPv6 daddr (hi --- lo): %x --- %x", ipv6DaddrHi, ipv6DaddrLo);

			bpf_printk("IPv6 flow_lbl: %x --- %x --- %x", flowLblHi, flowLblMi, flowLblLo);
		#endif

		// Declare the struct we'll use to index the map
		struct fourTuple flowHash;

		// Initialise the struct with 0s. This is necessary for some reason to do
		// with compiler padding. Check that's the case...
		__builtin_memset(&flowHash, 0, sizeof(flowHash));

		// Fake the port numbers: there are none on ICPM!
		flowHash.ip6Hi = ipv6DaddrHi;
		flowHash.ip6Lo = ipv6DaddrLo;
		flowHash.dPort = 5777;
		flowHash.sPort = 2345;
	
		__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);

		if (!flowTag) {
			bpf_printk("found no entry in the map...");
		} else {
			bpf_printk("retrieved flowTag: %u", *flowTag);

			// Embed the configured flowTag into the IPv6 header.
			l3->flow_lbl[0] = (*flowTag & ( 0xF << 16)) >> 16;
			l3->flow_lbl[1] = (*flowTag & (0xFF <<  8)) >> 8;
			l3->flow_lbl[2] = *flowTag & 0xFF;

			return TC_ACT_OK;
		}

		// If there was no match, simply force the whole flow label to 1.
		l3->flow_lbl[2] = 0xFF;
		l3->flow_lbl[1] = 0xFF;
		l3->flow_lbl[0] = 0xF;

		return TC_ACT_OK;
	}

	if (l3->nexthdr == PROTO_TCP) {
		l4 = (void *)(l3 + 1);
		if ((void *)(l4 + 1) > data_end)
			return TC_ACT_OK;

		#ifdef GLOWD_DEBUG
			bpf_printk("TCP source: %x", bpf_htons(l4->source));
			bpf_printk("  TCP dest: %x", bpf_htons(l4->dest));
		#endif
	}

	// At this point we have access to the full IPv6 header and payload. Time to mark the packet!

	// Simply signal that the packet should proceed!
	return TC_ACT_OK;
}

// Oh wow, the kernel refuses to load unlicensed stuff!
char LICENSE[] SEC("license") = "GPL";
