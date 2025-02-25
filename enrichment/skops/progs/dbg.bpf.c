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

static __always_inline void print_tcp_info(struct flowd_tcp_info* tcpi) {
	bpf_printk("TCP INFO STRUCT:");
	bpf_printk("\tstate=%u",                     tcpi->tcpi_state);
	bpf_printk("\tsk_pacing_rate=%llu",          tcpi->tcpi_pacing_rate);
	bpf_printk("\tsk_max_pacing_rate=%llu",      tcpi->tcpi_max_pacing_rate);
	bpf_printk("\treordering=%u",                tcpi->tcpi_reordering);
	bpf_printk("\tsnd_cwnd=%u",                  tcpi->tcpi_snd_cwnd);
	bpf_printk("\tca_state=%u",                  tcpi->tcpi_ca_state);
	bpf_printk("\tretransmits=%u",               tcpi->tcpi_retransmits);
	bpf_printk("\tprobes_out=%u",                tcpi->tcpi_probes);
	bpf_printk("\tbackoff=%u",                   tcpi->tcpi_backoff);
	bpf_printk("\toptions=%u",                   tcpi->tcpi_options);
	bpf_printk("\tsnd_wscale=%u",                tcpi->tcpi_snd_wscale);
	bpf_printk("\trcv_wscale=%u",                tcpi->tcpi_rcv_wscale);
	bpf_printk("\trto=%u",                       tcpi->tcpi_rto);
	bpf_printk("\tato=%u",                       tcpi->tcpi_ato);
	bpf_printk("\tsnd_mss=%u",                   tcpi->tcpi_snd_mss);
	bpf_printk("\trcv_mss=%u",                   tcpi->tcpi_rcv_mss);
	bpf_printk("\tunacked=%u",                   tcpi->tcpi_unacked);
	bpf_printk("\tsacked=%u",                    tcpi->tcpi_sacked);
	bpf_printk("\tlost=%u",                      tcpi->tcpi_lost);
	bpf_printk("\tretrans=%u",                   tcpi->tcpi_retrans);
	bpf_printk("\tlast_data_sent=%u",            tcpi->tcpi_last_data_sent);
	bpf_printk("\tlast_data_recv=%u",            tcpi->tcpi_last_data_recv);
	bpf_printk("\tlast_ack_recv=%u",             tcpi->tcpi_last_ack_recv);
	bpf_printk("\tpmtu=%u",                      tcpi->tcpi_pmtu);
	bpf_printk("\trcv_ssthresh=%u",              tcpi->tcpi_rcv_ssthresh);
	bpf_printk("\trtt=%u",                       tcpi->tcpi_rtt);
	bpf_printk("\trttvar=%u",                    tcpi->tcpi_rttvar);
	bpf_printk("\tadvmss=%u",                    tcpi->tcpi_advmss);
	bpf_printk("\trcv_rtt=%u",                   tcpi->tcpi_rcv_rtt);
	bpf_printk("\trcv_space=%u",                 tcpi->tcpi_rcv_space);
	bpf_printk("\ttotal_retrans=%u",             tcpi->tcpi_total_retrans);
	bpf_printk("\tbytes_acked=%u",               tcpi->tcpi_bytes_acked);
	bpf_printk("\tbytes_received=%u",            tcpi->tcpi_bytes_received);
	bpf_printk("\tnotsent_bytes=%u",             tcpi->tcpi_notsent_bytes);
	bpf_printk("\tsegs_out=%u",                  tcpi->tcpi_segs_out);
	bpf_printk("\tsegs_in=%u",                   tcpi->tcpi_segs_in);
	bpf_printk("\tmin_rtt=%u",                   tcpi->tcpi_min_rtt);
	bpf_printk("\tdata_segs_in=%u",              tcpi->tcpi_data_segs_in);
	bpf_printk("\tdata_segs_out=%u",             tcpi->tcpi_data_segs_out);
	bpf_printk("\tdelivery_rate_app_limited=%u", tcpi->tcpi_delivery_rate_app_limited);
	bpf_printk("\tdelivery_rate=%u",             tcpi->tcpi_delivery_rate);
	bpf_printk("\tdelivered=%u",                 tcpi->tcpi_delivered);
	bpf_printk("\tdelivered_ce=%u",              tcpi->tcpi_delivered_ce);
	bpf_printk("\tbytes_sent=%u",                tcpi->tcpi_bytes_sent);
	bpf_printk("\tbytes_retrans=%u",             tcpi->tcpi_bytes_retrans);
	bpf_printk("\tdsack_dups=%u",                tcpi->tcpi_dsack_dups);
	bpf_printk("\treord_seen=%u",                tcpi->tcpi_reord_seen);
	bpf_printk("\trcv_ooopack=%u",               tcpi->tcpi_rcv_ooopack);
	bpf_printk("\tsnd_wnd=%u",                   tcpi->tcpi_snd_wnd);
	bpf_printk("\tfastopen_client_fail=%u",      tcpi->tcpi_fastopen_client_fail);
}
