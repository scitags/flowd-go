#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// For TCP_INFO socket option, from tcp.h
#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8 /* ECN was negociated at TCP session init */
#define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
#define TCPI_OPT_USEC_TS	64 /* usec timestamps */

// From tcp.h
#define	TCP_ECN_OK		1
#define	TCP_ECN_QUEUE_CWR	2
#define	TCP_ECN_DEMAND_CWR	4
#define	TCP_ECN_SEEN		8

static __always_inline void print_tcp_info(struct tcp_info* tcpi) {
	bpf_printk("state=%d",              tcpi->tcpi_state);
	bpf_printk("sk_pacing_rate=%d",     tcpi->tcpi_pacing_rate);
	bpf_printk("sk_max_pacing_rate=%d", tcpi->tcpi_max_pacing_rate);
	bpf_printk("reordering=%d",         tcpi->tcpi_reordering);
	bpf_printk("snd_cwnd=%d",           tcpi->tcpi_snd_cwnd);
	bpf_printk("ca_state=%x",           tcpi->tcpi_ca_state);
	bpf_printk("retransmits=%d",        tcpi->tcpi_retransmits);
	bpf_printk("probes_out=%d",         tcpi->tcpi_probes);
	bpf_printk("backoff=%d",            tcpi->tcpi_backoff);
	bpf_printk("options=%x",            tcpi->tcpi_options);
	bpf_printk("snd_wscale=%d",         tcpi->tcpi_snd_wscale);
	bpf_printk("rcv_wscale=%d\n",       tcpi->tcpi_rcv_wscale);
}

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
 * This function is a reimplementation of the kernel's own tcp_get_info. Be sure to
 * check https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L4056 for
 * the actual implementation. Be sure to also take a look at
 * https://github.com/iovisor/bcc/blob/db3234f07679cd8f7632576966a82874ff2a7d21/libbpf-tools/tcplife.bpf.c
 * Also, be sure to check the CORE reference at https://nakryiko.com/posts/bpf-core-reference-guide
 */
static __always_inline void tcp_get_info(struct tcp_sock *tp, __u32 state, struct tcp_info *info) {
	// We can perform these casts given the layout of 'struct tcp_sock': the first memory
	// chunk is that of a 'struct sock' and that of a 'struct inet_connection_sock' too!
	// We just need to take a look at vmlinux.h to confirm that... Be sure to check
	// https://stackoverflow.com/questions/38201991/how-is-one-structure-mapped-to-another-by-something-like-return-struct-a-b
	struct sock *sk = (struct sock*)tp;
	struct inet_connection_sock *icsk = (struct inet_connection_sock*)tp;

	int err;

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
}
