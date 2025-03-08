#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "sk_ops.bpf.h"

/*
 * A crude reimplementation of jiffies_to_msecs [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/kernel/time/time.c#L374
 */
static __always_inline __u64 jiffies_to_msecs(__u64 j) {
	/*
	 * If we didn't manage to read the value of CONFIG_HZ from Kconfig
	 * variables (i.e. it's a 0) assume HZ is 1000 which it'll probably
	 * be anyway...
	 */
	if (!CONFIG_HZ)
		return (MSEC_PER_SEC / DEFAULT_HZ) * j;
	return (MSEC_PER_SEC / (__u32) CONFIG_HZ) * j;
}

/*
 * A crude reimplementation of jiffies_to_usecs [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/kernel/time/time.c#L391
 */
 static __always_inline __u64 jiffies_to_usecs(__u64 j) {
	/*
	 * If we didn't manage to read the value of CONFIG_HZ from Kconfig
	 * variables (i.e. it's a 0) assume HZ is 1000 which it'll probably
	 * be anyway...
	 */
	if (!CONFIG_HZ)
		return (USEC_PER_SEC / DEFAULT_HZ) * j;
	return (USEC_PER_SEC / (__u32) CONFIG_HZ) * j;
}

/*
 * A crude reimplementation of tcp_compute_delivery_rate [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L398
 */
static __always_inline __u64 tcp_compute_delivery_rate(const struct tcp_sock *tp) {
	__u32 rate = BPF_CORE_READ(tp, rate_delivered);
	__u32 intv = BPF_CORE_READ(tp, rate_interval_us);
	__u32 mss_cache = BPF_CORE_READ(tp, mss_cache);
	__u64 rate64 = 0;

	if (rate && intv && mss_cache) {
		rate64 = (u64)rate * mss_cache * USEC_PER_SEC;
		/*
		 * Check the implementation of do_div [0]. It basically carries out
		 * the division and implicitly assigns the result to n (i.e. the
		 * dividend, as expected). It also returns the remainder, which in
		 * this case is simply ignored. Long story short: this is a truncating
		 * division.
		 *   0: https://elixir.bootlin.com/linux/v5.14/source/include/asm-generic/div64.h#L31
		 */
		rate64 = rate64 / intv;
	}
	return rate64;
}

/*
 * A crude reimplementation of tcp_get_info_chrono_stats [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L3663
 */
static __always_inline void tcp_get_info_chrono_stats(const struct tcp_sock *tp, struct flowd_tcp_info *info) {
	__u64 stats[__TCP_CHRONO_MAX], total = 0;
	enum tcp_chrono i;

	__u64 hz = DEFAULT_HZ;
	if (CONFIG_HZ)
		hz = CONFIG_HZ;

	for (i = TCP_CHRONO_BUSY; i < __TCP_CHRONO_MAX; ++i) {
		stats[i] = BPF_CORE_READ(tp, chrono_stat[i - 1]);
		if (i == BPF_CORE_READ_BITFIELD_PROBED(tp, chrono_type))
			stats[i] += bpf_jiffies64() - BPF_CORE_READ(tp, chrono_start);
		stats[i] *= USEC_PER_SEC / hz;
		total += stats[i];
	}

	info->tcpi_busy_time = total;
	info->tcpi_rwnd_limited = stats[TCP_CHRONO_RWND_LIMITED];
	info->tcpi_sndbuf_limited = stats[TCP_CHRONO_SNDBUF_LIMITED];
}

/*
 * This function is a reimplementation of the kernel's own tcp_get_info [0]. Be sure to
 * take a look at [1] for a great example based on libbpf and [2] for the CO:RE reference
 * guide. On [3] there are many more valuable libbpf-based:
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp.c#L3683
 *   1: https://github.com/iovisor/bcc/blob/db3234f07679cd8f7632576966a82874ff2a7d21/libbpf-tools/tcplife.bpf.c
 *   2: https://nakryiko.com/posts/bpf-core-reference-guide
 *   3: https://github.com/iovisor/bcc/tree/master/libbpf-tools
 */
static __always_inline void tcp_get_info(struct tcp_sock *tp, __u32 state, struct flowd_tcp_info *info) {
	/*
	 * We can perform these casts given the layout of 'struct tcp_sock': the first memory
	 * chunk is that of a 'struct sock' and that of a 'struct inet_connection_sock' too!
	 * This is actually like this by design: check [0], [1], [2] and [3]. Also, [4] sheds some
	 * light on this casting and how it only affects offsets from the base address tp.
	 *   0: https://elixir.bootlin.com/linux/v5.14/source/include/linux/tcp.h#L145
	 *   1: https://elixir.bootlin.com/linux/v5.14/source/include/net/inet_connection_sock.h#L82
	 *   2: https://elixir.bootlin.com/linux/v5.14/source/include/net/inet_sock.h#L195
	 *   3: https://elixir.bootlin.com/linux/v5.14/source/include/net/sock.h#L251
	 *   4: https://stackoverflow.com/questions/38201991/how-is-one-structure-mapped-to-another-by-something-like-return-struct-a-b
	 */
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
	 * Jiffies are the internal ticks in the Linux kernel whose frequency is
	 * determined by the HZ constant in the kernel's source. This constant is
	 * usually specified as a kernel configuration parameter (Kconfig) when
	 * compiling it. Even though it's by no means an authoritative answer, one
	 * can get the current kernel's HZ value with:
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
	 * configuration as explained in [1]. The running kernel's configuration can
	 * also be inspected through proc_config.gz(5) [2].
	 *   0: https://elixir.bootlin.com/linux/v5.14/source/kernel/time/time.c#L374
	 *   1: https://elixir.bootlin.com/linux/v5.14/source/kernel/Kconfig.hz
	 *   2: https://www.man7.org/linux/man-pages/man5/proc_config.gz.5.html
	 */
	bpf_printk("rto: %llu", jiffies_to_usecs(BPF_CORE_READ(icsk, icsk_rto)));
	bpf_printk("ato: %llu", jiffies_to_usecs(BPF_CORE_READ(icsk, icsk_ack.ato)));

	info->tcpi_rto = jiffies_to_usecs(BPF_CORE_READ(icsk, icsk_rto));
	info->tcpi_ato = jiffies_to_usecs(BPF_CORE_READ(icsk, icsk_ack.ato));
	err = BPF_CORE_READ_INTO(&info->tcpi_snd_mss, tp, mss_cache);
	if (err) {
		bpf_printk("error performing CORE read of mss_cache: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_rcv_mss, icsk, icsk_ack.rcv_mss);
	if (err) {
		bpf_printk("error performing CORE read of icsk_ack.rcv_mss: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_unacked, tp, packets_out);
	if (err) {
		bpf_printk("error performing CORE read of packets_out: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_sacked, tp, sacked_out);
	if (err) {
		bpf_printk("error performing CORE read of sacked_out: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_lost, tp, lost_out);
	if (err) {
		bpf_printk("error performing CORE read of lost_out: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_retrans, tp, retrans_out);
	if (err) {
		bpf_printk("error performing CORE read of retrans_out: %d", err);
	}

	__u64 now = bpf_jiffies64();
	info->tcpi_last_data_sent = jiffies_to_msecs(now - BPF_CORE_READ(tp, lsndtime));
	info->tcpi_last_data_recv = jiffies_to_msecs(now - BPF_CORE_READ(icsk, icsk_ack.lrcvtime));
	info->tcpi_last_ack_recv = jiffies_to_msecs(now - BPF_CORE_READ(tp, rcv_tstamp));

	err = BPF_CORE_READ_INTO(&info->tcpi_pmtu, icsk, icsk_pmtu_cookie);
	if (err) {
		bpf_printk("error performing CORE read of icsk_pmtu_cookie: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_rcv_ssthresh, tp, rcv_ssthresh);
	if (err) {
		bpf_printk("error performing CORE read of rcv_ssthresh: %d", err);
	}
	info->tcpi_rtt = BPF_CORE_READ(tp, srtt_us) >> 3;
	info->tcpi_rttvar = BPF_CORE_READ(tp, mdev_us) >> 2;
	err = BPF_CORE_READ_INTO(&info->tcpi_snd_ssthresh, tp, snd_ssthresh);
	if (err) {
		bpf_printk("error performing CORE read of snd_ssthresh: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_advmss, tp, advmss);
	if (err) {
		bpf_printk("error performing CORE read of advmss: %d", err);
	}

	info->tcpi_rcv_rtt = BPF_CORE_READ(tp, rcv_rtt_est.rtt_us) >> 3;
	err = BPF_CORE_READ_INTO(&info->tcpi_rcv_space, tp, rcvq_space.space);
	if (err) {
		bpf_printk("error performing CORE read of rcvq_space.space: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_total_retrans, tp, total_retrans);
	if (err) {
		bpf_printk("error performing CORE read of total_retrans: %d", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_bytes_acked, tp, bytes_acked);
	if (err) {
		bpf_printk("error performing CORE read of bytes_acked: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_bytes_received, tp, bytes_received);
	if (err) {
		bpf_printk("error performing CORE read of bytes_received: %d", err);
	}

	__u32 write_seq = BPF_CORE_READ(tp, write_seq);
	__u32 snd_nxt = BPF_CORE_READ(tp, snd_nxt);

	/*
	 * Note we ZERO OUT info, so we needn't consider the case where the
	 * subtraction is negative.
	 */
	if (write_seq - snd_nxt > 0)
		info->tcpi_notsent_bytes = write_seq - snd_nxt;
	tcp_get_info_chrono_stats(tp, info);

	err = BPF_CORE_READ_INTO(&info->tcpi_segs_out, tp, segs_out);
	if (err) {
		bpf_printk("error performing CORE read of segs_out: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_segs_in, tp, segs_in);
	if (err) {
		bpf_printk("error performing CORE read of segs_in: %d", err);
	}

	/*
	 * tcp_min_rtt simply extracts tp->rtt_min which is a struct minmax.
	 * It calls minmax_get [0] on it, which basically returns the first measure.
	 * We'll simply do this manually and avoid defining yet another function.
	 *   0: https://elixir.bootlin.com/linux/v5.14/source/include/linux/win_minmax.h#L22
	 */
	err = BPF_CORE_READ_INTO(&info->tcpi_min_rtt, tp, rtt_min.s[0].v);
	if (err) {
		bpf_printk("error performing CORE read of rtt_min.s[0].v: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_data_segs_in, tp, data_segs_in);
	if (err) {
		bpf_printk("error performing CORE read of data_segs_in: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_data_segs_out, tp, data_segs_out);
	if (err) {
		bpf_printk("error performing CORE read of data_segs_out: %d", err);
	}

	info->tcpi_delivery_rate_app_limited = BPF_CORE_READ_BITFIELD_PROBED(tp, rate_app_limited) ? 1 : 0;
	__u64 rate64 = tcp_compute_delivery_rate(tp);
	if (rate64)
		info->tcpi_delivery_rate = rate64;
	err = BPF_CORE_READ_INTO(&info->tcpi_delivered, tp, delivered);
	if (err) {
		bpf_printk("error performing CORE read of delivered: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_delivered_ce, tp, delivered_ce);
	if (err) {
		bpf_printk("error performing CORE read of delivered_ce: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_bytes_sent, tp, bytes_sent);
	if (err) {
		bpf_printk("error performing CORE read of bytes_sent: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_bytes_retrans, tp, bytes_retrans);
	if (err) {
		bpf_printk("error performing CORE read of bytes_retrans: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_dsack_dups, tp, dsack_dups);
	if (err) {
		bpf_printk("error performing CORE read of dsack_dups: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_reord_seen, tp, reord_seen);
	if (err) {
		bpf_printk("error performing CORE read of reord_seen: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_rcv_ooopack, tp, rcv_ooopack);
	if (err) {
		bpf_printk("error performing CORE read of rcv_ooopack: %d", err);
	}
	err = BPF_CORE_READ_INTO(&info->tcpi_snd_wnd, tp, snd_wnd);
	if (err) {
		bpf_printk("error performing CORE read of snd_wnd: %d", err);
	}
	info->tcpi_fastopen_client_fail = BPF_CORE_READ_BITFIELD(tp, fastopen_client_fail);
}
