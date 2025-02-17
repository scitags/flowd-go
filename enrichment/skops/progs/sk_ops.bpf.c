// Plundered from https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS :)
// Use https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS as a general
// reference.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "sk_ops.bpf.h"

#include "utils.bpf.c"

// static __always_inline int handleDatagram(struct __sk_buff *ctx, struct ipv6hdr *l3, void *data_end) {
// 	// If running in debug mode we'll handle ICMP messages as well
// 	// as TCP segments. That way we can leverage ping(8) to easily
// 	// generate traffic...
// 	#ifdef GLOWD_DEBUG
// 		if (l3->nexthdr == PROTO_IPV6_ICMP)
// 			return handleICMP(ctx, l3);
// 	#endif

// 	// We'll only handle TCP traffic flows
// 	if (l3->nexthdr == PROTO_TCP) {
// 		return handleTCP(ctx, l3, data_end);
// 	}

// 	// Simply signal that the packet should proceed!
// 	return TC_ACT_OK;

// 	flowHash.ip6Hi = ipv6DaddrHi;
// 	flowHash.ip6Lo = ipv6DaddrLo;
// 	flowHash.dPort = bpf_htons(l4->dest);
// 	flowHash.sPort = bpf_htons(l4->source);

// 	// Check if a flow with the above criteria has been defined by flowd-go
// 	__u32 *flowTag = bpf_map_lookup_elem(&flowLabels, &flowHash);
// }

// static __always_inline void handleClosingConnection() {
// 	// Declare the struct we'll use to index the map
// 	struct fourTuple flowHash;

// 	// Initialise the struct with 0s. This is necessary for some reason to do
// 	// with compiler padding. Check that's the case...
// 	__builtin_memset(&flowHash, 0, sizeof(flowHash));

// 	__u64 ipv6DaddrLo = ipv6AddrLo(l3->daddr);
// 	__u64 ipv6DaddrHi = ipv6AddrHi(l3->daddr);
// 	flowHash.ip6Hi = ipv6DaddrHi;
// 	flowHash.ip6Lo = ipv6DaddrLo;
// 	flowHash.dPort = bpf_htons(l4->dest);
// 	flowHash.sPort = bpf_htons(l4->source);

// 	key = 1, value = 5678;
// 	result = bpf_map_update_elem(&my_map, &key, &value, BPF_NOEXIST);
// }

/*
 * Indispensable refs:
 *   - https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS/#sk
 *   - https://github.com/torvalds/linux/blob/master/samples/bpf/tcp_bpf.readme
 *   - https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html
 *   - https://www.man7.org/linux/man-pages/man7/cgroups.7.html
 *   - https://eunomia.dev/tutorials/14-tcpstates/#tcpstate-ebpf-code
 *   - https://eunomia.dev/tutorials/13-tcpconnlat/#ebpf-implementation-of-tcpconnlat
 *   - https://brendangregg.com/blog/2018-03-22/tcp-tracepoints.html
 *   - https://github.com/iovisor/bcc/blob/master/tools/tcpcong.py
 *   - https://leighfinch.net/2024/02/05/ebpf-tracepoints-gaining-access-to-the-tcp-state-machine/
 *   - https://elixir.bootlin.com/linux/v6.12.4/source/samples/bpf/tcp_basertt_kern.c#L48
 *   - https://elixir.bootlin.com/linux/v6.12.4/source/include/net/sock.h#L2225
 *   - https://elixir.bootlin.com/linux/v6.12.4/source/net/ipv4/tcp.c#L4055
 *   - https://netdevconf.info/2.2/papers/brakmo-tcpbpf-talk.pdf
 *   - https://github.com/bytedance/Elkeid
 */

SEC("sockops")
int connTracker(struct bpf_sock_ops *ctx) {
	struct bpf_tcp_sock *bpf_tcp_sk;
	struct tcp_sock *tp_sk;
	struct bpf_sock *sk;

	switch (ctx->op) {
		// When the connection starts up make sure this program is notified about
		// TCP state changes.
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_STATE_CB_FLAG);
			return 1;

		case BPF_SOCK_OPS_STATE_CB:
			bpf_printk("state change from %d to %d (%d) [%d]\n", ctx->args[0], ctx->args[1], ctx->is_fullsock, ctx->state);

			if (!ctx->is_fullsock) {
				bpf_printk("we don't have a 'full' socket...\n");
				return 1;
			}

			sk = ctx->sk;
			if (!sk)
				return 1;

			bpf_tcp_sk = bpf_tcp_sock(sk);
			if (!bpf_tcp_sk)
				return 1;

			bpf_printk("dsack_dups=%u delivered=%u\n",
				bpf_tcp_sk->dsack_dups, bpf_tcp_sk->delivered);
			bpf_printk("delivered_ce=%u icsk_retransmits=%u\n",
				bpf_tcp_sk->delivered_ce, bpf_tcp_sk->icsk_retransmits);

			tp_sk = bpf_skc_to_tcp_sock(sk);
			if (!tp_sk)
				return 1;

			bpf_printk("mss_cache=%d\n", tp_sk->mss_cache);
			bpf_printk("icsk_rto_min=%d\n", tp_sk->inet_conn.icsk_rto_min);
			bpf_printk("name=%s\n", tp_sk->inet_conn.icsk_ca_ops->name);
			bpf_printk("rmem_alloc=%d\n", tp_sk->inet_conn.icsk_inet.sk.sk_backlog.rmem_alloc);
			bpf_printk("rcv_buff=%d\n", tp_sk->inet_conn.icsk_inet.sk.sk_rcvbuf);

			return 1;
			// break;
		default:
			return 1;
	}

	return 1;
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
