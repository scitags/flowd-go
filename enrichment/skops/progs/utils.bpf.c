#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "sk_ops.bpf.h"

/* These functions determine how the current flow behaves in respect of SACK
 * handling. SACK is negotiated with the peer, and therefore it can vary
 * between different flows. Pulled from https://elixir.bootlin.com/linux/v6.13.3/source/include/net/tcp.h#L1269
 *
 * tcp_is_sack - SACK enabled
 * tcp_is_reno - No SACK
 */
// static __always_inline int tcp_is_sack(const struct tcp_sock *tp) {
// 	return BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.sack_ok);
// }

// static __always_inline bool tcp_is_reno(const struct tcp_sock *tp) {
// 	return !tcp_is_sack(tp);
// }

/*
 * A crude reimplementation of jiffies_to_msecs [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/kernel/time/time.c#L374
 */
static __always_inline __u64 jiffies_to_msecs(__u64 j) {
	// If we didn't manage to read the value of CONFIG_HZ from Kconfig
	// variables (i.e. it's a 0) assume HZ is 1000 which it'll likely be.
	if (!CONFIG_HZ)
		return (MSEC_PER_SEC / 1000L) * j;
	return (MSEC_PER_SEC / CONFIG_HZ) * j;
}

/*
 * This function is a reimplementation of the kernel's own tcp_get_info. Be sure to
 * check https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L3683 for
 * the actual implementation. Be sure to also take a look at [0] for a great example
 * based on libbpf and [1] for the CO:RE reference guide. On [2] there are many more
 * libbpf-based examples containing troves of valuable examples:
 *   0: https://github.com/iovisor/bcc/blob/db3234f07679cd8f7632576966a82874ff2a7d21/libbpf-tools/tcplife.bpf.c
 *   1: https://nakryiko.com/posts/bpf-core-reference-guide
 *   2: https://github.com/iovisor/bcc/tree/master/libbpf-tools
 */
static __always_inline void tcp_get_info(struct tcp_sock *tp, __u32 state, struct tcp_info *info) {
	// We can perform these casts given the layout of 'struct tcp_sock': the first memory
	// chunk is that of a 'struct sock' and that of a 'struct inet_connection_sock' too!
	// We just need to take a look at vmlinux.h to confirm that... Be sure to check
	// https://stackoverflow.com/questions/38201991/how-is-one-structure-mapped-to-another-by-something-like-return-struct-a-b
	struct sock *sk = (struct sock*)tp;
	struct inet_connection_sock *icsk = (struct inet_connection_sock*)tp;

	int err;

	// Zero out the struct before populating it!
	__builtin_memset(info, 0, sizeof(*info));

	info->tcpi_state = state;

	err = BPF_CORE_READ_INTO(&info->tcpi_pacing_rate, sk, sk_pacing_rate);
	if (err) {
		bpf_printk("error performing CORE read of sk_pacing_rate: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_max_pacing_rate, sk, sk_max_pacing_rate);
	if (err) {
		bpf_printk("error performing CORE read of sk_max_pacing_rate: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_reordering, tp, reordering);
	if (err) {
		bpf_printk("error performing CORE read of reordering: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_snd_cwnd, tp, snd_cwnd);
	if (err) {
		bpf_printk("error performing CORE read of snd_cwnd: %d", err);
	}

	info->tcpi_ca_state = BPF_CORE_READ_BITFIELD_PROBED(icsk, icsk_ca_state);

	err = BPF_CORE_READ_INTO(&info->tcpi_retransmits, icsk, icsk_retransmits);
	if (err) {
		bpf_printk("error performing CORE read of icsk_retransmits: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_probes, icsk, icsk_probes_out);
	if (err) {
		bpf_printk("error performing CORE read of icsk_probes_out: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_backoff, icsk, icsk_backoff);
	if (err) {
		bpf_printk("error performing CORE read of icsk_backoff: %d", err);
	}

	if (BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.tstamp_ok))
		info->tcpi_options |= TCPI_OPT_TIMESTAMPS;
	if (BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.sack_ok)) // tcp_is_sack()
		info->tcpi_options |= TCPI_OPT_SACK;
	if (BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.wscale_ok)) {
		info->tcpi_options |= TCPI_OPT_WSCALE;
		info->tcpi_snd_wscale = BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.snd_wscale);
		info->tcpi_rcv_wscale = BPF_CORE_READ_BITFIELD_PROBED(tp, rx_opt.rcv_wscale);
	}

	if (BPF_CORE_READ(tp, ecn_flags) & TCP_ECN_OK)
		info->tcpi_options |= TCPI_OPT_ECN;
	if (BPF_CORE_READ(tp, ecn_flags) & TCP_ECN_SEEN)
		info->tcpi_options |= TCPI_OPT_ECN_SEEN;
	if (BPF_CORE_READ_BITFIELD_PROBED(tp, syn_data_acked))
		info->tcpi_options |= TCPI_OPT_SYN_DATA;

	/*
	 * Note: jiffies are the internal ticks in the Linux kernel whose frequency is
	 * determined by the HZ constant in the kernel's source. This constant is
	 * usually specified as a kernel configuration parameter. Even though it's by
	 * no means an authoritative answer, one can get the current kernel's HZ value
	 * with:
	 *   $ grep 'CONFIG_HZ=' /boot/config-$(uname -r)
	 *   CONFIG_HZ=1000
	 * A value of 1000 is fairly common nowadays (the above was executed on a 5.14
	 * kernel). As seen in functions such as jiffies_to_msec [0], this value is used
	 * as a conversion factor for transforming these kernel-specific jiffies into
	 * actual time values. The tcp_sock structure has several timers expressed in
	 * jiffies, and so it becomes necessary to leverage all this to convert them
	 * to meaningful figures. Bear in mind the bpf_jiffies64() BPF helper allows
	 * a BPF program to access the current jiffies on a running kernel, thus
	 * enabling us to compute jiffy differences as is done in the tcp_get_info()
	 * implementation in the kernel. The HZ value is chosen based on the kernel's
	 * configuration as explained in [1].
	 *   0: https://elixir.bootlin.com/linux/v5.14/source/kernel/time/time.c#L374
	 *   1: https://elixir.bootlin.com/linux/v5.14/source/kernel/Kconfig.hz
	 */
	// info->tcpi_rto = BPF_CORE_READ(icsk, icsk_rto) / 
}
