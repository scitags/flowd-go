// +build ignore

/*
 * The authoritative reference is the Kernel documentation over at [0].
 * Be sure to check bpf-helpers(7) [1] too!
 * References:
 *   0: https://www.kernel.org/doc/html/latest/bpf/index.html
 *   1: https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
 */

// You'll need to install libbpf-devel (or the equivalent one) to get these headers!
#include <linux/bpf.h>

// Oh wow, the kernel refuses to load unlicensed stuff!
char LICENSE[] SEC("license") = "GPL";

// The keys for our hash maps. Should we maybe combine the ports into a __u32?
struct fourTuple {
	__u64 ip6_hi;
	__u64 ip6_lo;
	__u16 dport;
	__u16 sport;
};

// Let's define our map!
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, __u64);
} flowLabels SEC(".maps");

// long ringBufferFlags = 0;

// Let's hook the program on the TC! XDP will only look at the ingress traffic :(
SEC("tc")
int target(struct __sk_buff *skb) {
	// __u32 *pkt_count = bpf_map_lookup_elem(&flowLabels, &ip);
	// if (!pkt_count) {
	// 	// No entry in the map for this IP address yet, so set the initial value to 1.
	// 	__u32 init_pkt_count = 1;
	// 	bpf_map_update_elem(&flowLabels, &ip, &init_pkt_count, BPF_ANY);
	// } else {
	// 	// Entry already exists for this IP address,
	// 	// so increment it atomically using an LLVM built-in.
	// 	// Check https://llvm.org/docs/Atomics.html
	// 	__sync_fetch_and_add(pkt_count, 1);
	// }

	// Reserve space on the ringBuffer for the sample
	// process = bpf_ringbuf_reserve(&events, sizeof(int), ringBufferFlags);
	// if (!process) {
	// 	return 0;
	// }

	// *process = 2021;

	// bpf_ringbuf_submit(process, ringBufferFlags);
	return 0;
}

// BPF_HASH(flowlabel_table, struct fourtuple, u64, 100000);
// BPF_HASH(tobedeleted, struct fourtuple, u64, 100000);

// int set_flow_label(struct __sk_buff *skb) {
// 	u8 *cursor = 0;
// 	struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

// 	// IPv6
// 	if (ethernet->type == 0x86DD) {
// 		struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));

// 		struct fourtuple addrport;

// 		// This is necessary for some reason to do with compiler padding
// 		__builtin_memset(&addrport, 0, sizeof(addrport));

// 		addrport.ip6_hi = ip6->dst_hi;
// 		addrport.ip6_lo = ip6->dst_lo;

// 		// TCP
// 		if (ip6->next_header == 6) {
// 			struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

// 			addrport.dport = tcp->dst_port;
// 			addrport.sport = tcp->src_port;

// 			u64 *delete = tobedeleted.lookup(&addrport);

// 			u64 *flowlabel = flowlabel_table.lookup(&addrport);

// 			if (delete) {
// 				flowlabel_table.delete(&addrport);
// 				tobedeleted.delete(&addrport);
// 			}
// 			else if (flowlabel) {
// 				ip6->flow_label = *flowlabel;
// 			}
// 		}

// 		return -1;
// 	}
// 	// Handle vlan tag
// 	else if (ethernet->type == 0x8100)
// 	{
// 		struct dot1q_t *dot1q = cursor_advance(cursor, sizeof(*dot1q));

// 		if (dot1q->type == 0x86DD) {
// 			struct ip6_t *ip6 = cursor_advance(cursor, sizeof(*ip6));

// 			struct fourtuple addrport;

// 			// This is necessary for some reason to do with compiler padding
// 			__builtin_memset(&addrport, 0, sizeof(addrport));

// 			addrport.ip6_hi = ip6->dst_hi;
// 			addrport.ip6_lo = ip6->dst_lo;

// 			// TCP
// 			if (ip6->next_header == 6) {
// 				struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));

// 				addrport.dport = tcp->dst_port;
// 				addrport.sport = tcp->src_port;

// 				u64 *delete = tobedeleted.lookup(&addrport);

// 				u64 *flowlabel = flowlabel_table.lookup(&addrport);

// 				if (delete) {
// 					flowlabel_table.delete(&addrport);
// 					tobedeleted.delete(&addrport);
// 				}
// 				else if (flowlabel) {
// 					ip6->flow_label = *flowlabel;
// 				}
// 			}
// 			return -1;
// 		}
// 		else {
// 			return -1;
// 		}
// 	}
// 	else {
// 		return -1;
// 	}
// }
