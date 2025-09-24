#include "../vmlinux.h"
#include "watcher.bpf.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>

static __always_inline int submitFlow(struct bpf_sock_ops *ctx) {
	struct flowSpec *fs = bpf_ringbuf_reserve(&flowNots, sizeof(struct flowSpec), 0);
	if (!fs)
		return 1;

	fs->family = ctx->family;
	
	switch (fs->family) {
		case AF_INET:
			fs->sIpHi = fs->dIpHi = 0;
			fs->sIpLo = bpf_ntohl(ctx->local_ip4);
			fs->dIpLo = bpf_ntohl(ctx->remote_ip4);

			#if FLOWD_DEBUG
				__u32 rip = bpf_ntohl(ctx->remote_ip4);
				bpf_printk("watcher:            remote_ip4: %pI4", &ctx->remote_ip4);
				bpf_printk("watcher:            remote_ip4: %x", ctx->remote_ip4);
				bpf_printk("watcher: bpf_ntohl(remote_ip4): %pI4", &rip);
				bpf_printk("watcher: bpf_ntohl(remote_ip4): %x", bpf_ntohl(ctx->remote_ip4));
			#endif

			break;

		case AF_INET6:
			fs->sIpHi = (__u64) bpf_ntohl(ctx->local_ip6[0]) << 32ULL | bpf_ntohl(ctx->local_ip6[1]);
			fs->sIpLo = (__u64) bpf_ntohl(ctx->local_ip6[2]) << 32ULL | bpf_ntohl(ctx->local_ip6[3]);

			fs->dIpHi = (__u64) bpf_ntohl(ctx->remote_ip6[0]) << 32 | bpf_ntohl(ctx->remote_ip6[1]);
			fs->dIpLo = (__u64) bpf_ntohl(ctx->remote_ip6[2]) << 32 | bpf_ntohl(ctx->remote_ip6[3]);

			#if FLOWD_DEBUG
				bpf_printk("watcher: remote IPv6   : %pI6", ctx->remote_ip6);
				bpf_printk("watcher: remote IPv6[3]: %x",   ctx->remote_ip6[3]);
				bpf_printk("watcher: remote IPv6[2]: %x",   ctx->remote_ip6[2]);
				bpf_printk("watcher: remote IPv6[1]: %x",   ctx->remote_ip6[1]);
				bpf_printk("watcher: remote IPv6[0]: %x",   ctx->remote_ip6[0]);

				bpf_printk("watcher: local IPv6   : %pI6", ctx->local_ip6);
				bpf_printk("watcher: local IPv6[3]: %x",   ctx->local_ip6[3]);
				bpf_printk("watcher: local IPv6[2]: %x",   ctx->local_ip6[2]);
				bpf_printk("watcher: local IPv6[1]: %x",   ctx->local_ip6[1]);
				bpf_printk("watcher: local IPv6[0]: %x",   ctx->local_ip6[0]);

				bpf_printk("watcher: bpf_ntohl(local_ip6[3]): %x", bpf_ntohl(ctx->local_ip6[3]));
				bpf_printk("watcher: bpf_ntohl(local_ip6[2]): %x", bpf_ntohl(ctx->local_ip6[2]));
				bpf_printk("watcher: bpf_ntohl(local_ip6[1]): %x", bpf_ntohl(ctx->local_ip6[1]));
				bpf_printk("watcher: bpf_ntohl(local_ip6[0]): %x", bpf_ntohl(ctx->local_ip6[0]));

				bpf_printk("watcher: sIpHi: %016llx", fs->sIpHi);
				bpf_printk("watcher: sIpLo: %016llx", fs->sIpLo);
			#endif
	}

	#if FLOWD_DEBUG
		bpf_printk("watcher:            local_port : %d", ctx->local_port);
		bpf_printk("watcher: bpf_ntohl(remote_port): %d", bpf_ntohl(ctx->remote_port));
	#endif

	fs->sPort = ctx->local_port;
	fs->dPort = bpf_ntohl(ctx->remote_port);
	fs->state = ctx->args[1];

	/*
	 * Use an adaptative wakeup mechanism, we could also use BPF_RB_FORCE_WAKEUP or
	 * BPF_RB_NO_WAKEUP instead to control notifications to userspace. Bear in mind
	 * handling these manually is a sensitive and subtlety-riddled affair...
	 */
	bpf_ringbuf_submit(fs, 0);

	return 1;
}

SEC("sockops")
int watcher(struct bpf_sock_ops *ctx) {
	if (ctx->family != AF_INET && ctx->family != AF_INET6)
		return 1;

	#if FLOWD_DEBUG
		bpf_printk("watcher: local_port=%d (configured=[%d,%d])", ctx->local_port, MIN_SRC_PORT, MAX_SRC_PORT);
	#endif

	if (MIN_SRC_PORT != 0 && ctx->local_port < MIN_SRC_PORT)
		return 1;

	if (MAX_SRC_PORT != 0 && ctx->local_port > MAX_SRC_PORT)
		return 1;

	if (MIN_DST_PORT != 0 && bpf_ntohl(ctx->remote_port) < MIN_DST_PORT)
		return 1;

	if (MAX_DST_PORT != 0 && bpf_ntohl(ctx->remote_port) > MAX_DST_PORT)
		return 1;

	#if FLOWD_DEBUG
		bpf_printk("watcher: local_port=%d", ctx->local_port);
	#endif

	switch (ctx->op) {
		// Hook notifications for each TCP state change.
		case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
		case BPF_SOCK_OPS_TCP_CONNECT_CB:
			bpf_sock_ops_cb_flags_set(ctx, BPF_SOCK_OPS_STATE_CB_FLAG);

			return 1;

		// Let's look at the socket's statistics on state changes.
		case BPF_SOCK_OPS_STATE_CB:
			#ifdef FLOWD_DEBUG
				bpf_printk("watcher: state change from %d to %d (%d) [%d]", ctx->args[0], ctx->args[1], ctx->is_fullsock, ctx->state);
			#endif

			switch (ctx->args[1]) {
				case TCP_ESTABLISHED:
				case TCP_CLOSE:
					return submitFlow(ctx);
				default:
					return 1;
			}

		default:
			return 1;
	}
}

int _version SEC("version") = 1;
char _license[] SEC("license") = "GPL";
