// Plundered from https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS :)
// Use https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS as a general
// reference.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

#include "info.bpf.c"
#include "cong.bpf.c"
#include "dbg.bpf.c"

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
 *   - https://nakryiko.com/posts/libbpf-bootstrap/
 *   - https://nakryiko.com/posts/bcc-to-libbpf-howto-guide/#detecting-bcc-vs-libbpf-modes
 *   - https://nakryiko.com/posts/bpf-portability-and-co-re/
 *   - https://brendangregg.com/blog/2020-11-04/bpf-co-re-btf-libbpf.html
 *   - https://thegraynode.io/posts/portable_bpf_programs
 *   - https://mozillazg.com/2022/06/ebpf-libbpf-btf-powered-enabled-raw-tracepoint-common-questions-en.html
 */

static __always_inline int handleOp(struct bpf_sock_ops *ctx, bool ignorePollThrottle) {
	struct bpf_sock *sk;
	struct tcp_sock *tp;
	struct flowd_tcp_info *tcpi;

	// Only bother with IPv6 traffic
	if (ctx->family != AF_INET6)
		return 1;

	// Declare the struct we'll use to index the map
	struct flowSpec fSpec;

	// Initialise the struct with 0s. This is necessary for some reason to do
	// with compiler padding. Check that's the case...
	__builtin_memset(&fSpec, 0, sizeof(fSpec));

	// Hardcode the port numbers we'll 'look for': there are none in ICMP!
	fSpec.dPort = bpf_ntohl(ctx->remote_port);
	fSpec.sPort = ctx->local_port;

	// Check if a flow with the above criteria has been defined by flowd-go
	__u32 *dummy = bpf_map_lookup_elem(&flowsToFollow, &fSpec);

	// If there's a flow configured, mark the packet
	if (!dummy) {
		#ifdef FLOWD_DEBUG
			bpf_printk("bailing: no entry for this flow in the flowsToFollow map: dst: %d; src: %d", bpf_ntohl(ctx->remote_port), ctx->local_port);
		#endif
		return 1;
	}

	#ifdef FLOWD_POLL
		__u64 *next_dump;
		__u64 now;
	#endif

	sk = ctx->sk;
	if (!sk || !ctx->is_fullsock) {
		#ifdef FLOWD_DEBUG
			bpf_printk("bailing: no sk or it's not full: %p - %u", sk, ctx->is_fullsock);
		#endif
		return 1;
	}

	#ifdef FLOWD_POLL
		/*
		* Grab the last timestamp and create one if it doesn't exist! That's
		* what the BPF_SK_STORAGE_GET_F_CREATE flag is for :P Note the socket
		* must be a full sock (i.e. ctx->is_fullsock != 0) for this to work!
		*/
		next_dump = bpf_sk_storage_get(&pollAcc, sk, 0, BPF_SK_STORAGE_GET_F_CREATE);
		if (!next_dump)
			return 1;

		now = bpf_ktime_get_ns();
		if (!ignorePollThrottle) {
			if (now < *next_dump)
				return 1;
		}
		*next_dump = now + INTERVAL;
	#endif

	tp = bpf_skc_to_tcp_sock(sk);
	if (!tp) {
		#ifdef FLOWD_DEBUG
			bpf_printk("couldn't cast the bpf_sock pointer top a tcp_sock pointer");
		#endif
		return 1;
	}

	/*
	 * Reserve memory for a sample in the ring buffer. If we didn't manage to make
	 * the reservation we'll simply bail and avoid gathering all the info!
	 */
	tcpi = bpf_ringbuf_reserve(&tcpStats, sizeof(*tcpi), 0);
	if (!tcpi)
		return 1;

	tcp_get_info(tp, ctx->state, ctx->args[1], tcpi);
	tcp_get_cong_info(tp, tcpi);

	tcpi->src_port = (__u16) ctx->local_port;
	tcpi->dst_port = (__u16) bpf_ntohl(ctx->remote_port);

	// #ifdef FLOWD_DEBUG
	// 	print_flowd_tcp_info(tcpi);
	// 	print_flowd_tcp_info_bytes(tcpi);
	// #endif

	/*
	 * Use an adaptative wakeup mechanism, we could also use BPF_RB_FORCE_WAKEUP or
	 * BPF_RB_NO_WAKEUP instead to control notifications to userspace. Bear in mind
	 * handling these manually is a sensitive and subtlety-riddled affair...
	 */
	bpf_ringbuf_submit(tcpi, 0);

	return 1;
}

SEC("sockops")
int connTracker(struct bpf_sock_ops *ctx) {
	switch (ctx->op) {
		/*
		 * Hook notifications for each TCP state change.
		 */
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			#ifdef FLOWD_POLL
				bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG);
			#else
				bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_STATE_CB_FLAG);
			#endif

			#if FLOWD_DEBUG
				print_kconfig_variables();
			#endif

			return 1;

		/*
		 * Let's look at the socket's statistics on state changes.
		 */
		case BPF_SOCK_OPS_STATE_CB:
			#ifdef FLOWD_DEBUG
				bpf_printk("state change from %d to %d (%d) [%d]", ctx->args[0], ctx->args[1], ctx->is_fullsock, ctx->state);
			#endif
			return handleOp(ctx, true);

		/*
		 * Let's look at socket statistics every RTT
		 */
		case BPF_SOCK_OPS_RTT_CB:
			#ifdef FLOWD_POLL
				return handleOp(ctx, false);
			#endif

			return 1;
		default:
			return 1;
	}
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
