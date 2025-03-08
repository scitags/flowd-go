#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#include "sk_ops.bpf.h"

/*
 * Note that the cubic implementation defines no *_get_info function: do
 * we really want to take a look at the algorithm's contents in that case?
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_cubic.c
 */
static __always_inline void tcp_cubic_get_info() {}

/*
 * Note we don't do any CO:RE relocations as we'll already be reading eBPF
 * memory: we dump the entire icsk_ca_priv safely!
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_vegas.c#L290
 */
static __always_inline void tcp_vegas_get_info(struct vegas *ca) {
	bpf_printk("\t\tdoing_vegas_now: %u", ca->doing_vegas_now);
	bpf_printk("\t\tcntRTT:          %u", ca->cntRTT);
	bpf_printk("\t\tbaseRTT:         %u", ca->baseRTT);
	bpf_printk("\t\tminRTT:          %u", ca->minRTT);
}

/*
 * Check...
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_dctcp.c#L181
 */
// static __always_inline void tcp_dctcp_get_info(struct dctcp *ca, struct tcp_sock *tp) {
// 	bpf_printk("\t\tdctcp_enabled:  %u", 1);
// 	bpf_printk("\t\tdctcp_ce_state: %u", (__u16) BPF_CORE_READ(ca, ce_state));
// 	bpf_printk("\t\tdctcp_alpha:    %u", BPF_CORE_READ(ca, dctcp_alpha));
// 	bpf_printk("\t\tdctcp_ab_ecn:   %u", BPF_CORE_READ(tp, mss_cache) *
// 		(BPF_CORE_READ(tp, delivered_ce) - BPF_CORE_READ(ca, old_delivered_ce)));
// 	bpf_printk("\t\tdctcp_ab_tot:   %u", BPF_CORE_READ(tp, mss_cache) *
// 		(BPF_CORE_READ(tp, delivered) - BPF_CORE_READ(ca, old_delivered)));
// }

/*
 * This one's a bit of a pain to implement...
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_bbr.c#L1104
 */
// static __always_inline void tcp_bbr_get_info(struct bbr *ca, struct tcp_sock *tp) {}

/*
 * Libbpf tells us we cannot call this function... Check [0] for a list of available
 * Kfuncs.
 *   0: https://docs.ebpf.io/linux/kfuncs/
 */
// extern void tcp_get_info(struct sock *sk, struct tcp_info *info) __ksym;

static __always_inline __u8 getCaAlgEnum(char* caName, size_t caNameLen) {
	if (!bpf_strncmp(caName, caNameLen, "bbr")) {
		return FLOWD_CA_BBR;
	} else if (!bpf_strncmp(caName, caNameLen, "bic")) {
		return FLOWD_CA_BIC;
	} else if (!bpf_strncmp(caName, caNameLen, "cdg")) {
		return FLOWD_CA_CDG;
	} else if (!bpf_strncmp(caName, caNameLen, "reno")) {
		return FLOWD_CA_RENO;
	} else if (!bpf_strncmp(caName, caNameLen, "cubic")) {
		return FLOWD_CA_CUBIC;
	} else if (!bpf_strncmp(caName, caNameLen, "dctcp")) {
		return FLOWD_CA_DCTCP;
	} else if (!bpf_strncmp(caName, caNameLen, "dctcp-reno")) {
		return FLOWD_CA_DCTCP_RENO;
	} else if (!bpf_strncmp(caName, caNameLen, "highspeed")) {
		return FLOWD_CA_HIGHSPEED;
	} else if (!bpf_strncmp(caName, caNameLen, "htcp")) {
		return FLOWD_CA_HTCP;
	} else if (!bpf_strncmp(caName, caNameLen, "hybla")) {
		return FLOWD_CA_HYBLA;
	} else if (!bpf_strncmp(caName, caNameLen, "illinois")) {
		return FLOWD_CA_ILLINOIS;
	} else if (!bpf_strncmp(caName, caNameLen, "lp")) {
		return FLOWD_CA_LP;
	} else if (!bpf_strncmp(caName, caNameLen, "nv")) {
		return FLOWD_CA_NV;
	} else if (!bpf_strncmp(caName, caNameLen, "scalable")) {
		return FLOWD_CA_SCALABLE;
	} else if (!bpf_strncmp(caName, caNameLen, "vegas")) {
		return FLOWD_CA_VEGAS;
	} else if (!bpf_strncmp(caName, caNameLen, "veno")) {
		return FLOWD_CA_VENO;
	} else if (!bpf_strncmp(caName, caNameLen, "westwood")) {
		return FLOWD_CA_WESTWOOD;
	} else if (!bpf_strncmp(caName, caNameLen, "yeah")) {
		return FLOWD_CA_YEAH;
	}
	return FLOWD_CA_UNK;
}

static __always_inline void tcp_get_cong_info(struct tcp_sock *tp, struct flowd_tcp_info *info) {
	struct sock *sk = (struct sock*)tp;
	struct inet_connection_sock *icsk = (struct inet_connection_sock*)tp;

	int err;

	char caName[16];
	err = BPF_CORE_READ_STR_INTO(&caName, icsk, icsk_ca_ops, name);
	/*
	 * Please note the backing bpf_probe_read_kernel_str(7) returns the length of the read string
	 * on success or a negative value on error.
	 */
	if (err < 0) {
		bpf_printk("error performing CORE read of icsk_ca_ops->name: %u", err);
	}

	#ifdef FLOWD_DEBUG
		bpf_printk("detected ca=%s", caName);
	#endif

	err = BPF_CORE_READ_INTO(&info->tcpi_ca_key, icsk, icsk_ca_ops, key);
	if (err) {
		bpf_printk("error performing CORE read of icsk_ca_ops->key: %u", err);
	}

	err = BPF_CORE_READ_INTO(&info->tcpi_ca_flags, icsk, icsk_ca_ops, flags);
	if (err) {
		bpf_printk("error performing CORE read of icsk_ca_ops->flags: %u", err);
	}

	// Leave some wiggle room for the expected FLOWD_TCPI_CA_PRIV_SIZE elements
	__u64 caPriv[FLOWD_TCPI_CA_PRIV_SIZE];
	__builtin_memset(caPriv, 0xFF, sizeof(caPriv));

	__u8 caNameEnum = getCaAlgEnum(caName, sizeof(caName));

	info->tcpi_ca_alg = caNameEnum;

	/*
	 * Only dump ca private data for known algorithms
	 */
	if (caNameEnum != FLOWD_CA_UNK) {
		#ifdef FLOWD_DEBUG
			bpf_printk("attempting to read %d bytes from icsk_ca_priv (%p)", FLOWD_TCPI_CA_PRIV_SIZE * sizeof(__u64), &icsk->icsk_ca_priv);
		#endif

		if (bpf_core_read(&info->tcpi_ca_priv, FLOWD_TCPI_CA_PRIV_SIZE * sizeof(__u64), &icsk->icsk_ca_priv)) {
			bpf_printk("error reading caPriv...");
		}
	}
}
