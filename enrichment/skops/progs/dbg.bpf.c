#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#include "sk_ops.bpf.h"

/*
 * Check https://www.kernel.org/doc/html/latest/core-api/printk-formats.html for info
 * on format specifiers.
 */

static __always_inline void print_kconfig_variables() {
	bpf_printk("KCONFIG VARIABLES:");
	bpf_printk("\tCONFIG_HZ=%d", CONFIG_HZ);
}

static __always_inline void print_tcp_info(struct tcp_info* tcpi) {
	bpf_printk("TCP INFO STRUCT:");
	bpf_printk("\tstate=%u",                tcpi->tcpi_state);
	bpf_printk("\tsk_pacing_rate=%llu",     tcpi->tcpi_pacing_rate);
	bpf_printk("\tsk_max_pacing_rate=%llu", tcpi->tcpi_max_pacing_rate);
	bpf_printk("\treordering=%u",           tcpi->tcpi_reordering);
	bpf_printk("\tsnd_cwnd=%u",             tcpi->tcpi_snd_cwnd);
	bpf_printk("\tca_state=%u",             tcpi->tcpi_ca_state);
	bpf_printk("\tretransmits=%u",          tcpi->tcpi_retransmits);
	bpf_printk("\tprobes_out=%u",           tcpi->tcpi_probes);
	bpf_printk("\tbackoff=%u",              tcpi->tcpi_backoff);
	bpf_printk("\toptions=%u",              tcpi->tcpi_options);
	bpf_printk("\tsnd_wscale=%u",           tcpi->tcpi_snd_wscale);
	bpf_printk("\trcv_wscale=%u",           tcpi->tcpi_rcv_wscale);
}
