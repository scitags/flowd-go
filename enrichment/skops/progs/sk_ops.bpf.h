#ifndef __SKOPS_INC__
#define __SKOPS_INC__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// The keys for our hash maps. Should we maybe combine the ports into a __u32?
struct fourTuple {
	__u64 ip6Hi;
	__u64 ip6Lo;
	__u16 dPort;
	__u16 sPort;
};

// struct {
// 	// Store data locally on the socket (https://docs.kernel.org/bpf/map_sk_storage.html)
// 	__uint(type, BPF_MAP_TYPE_SK_STORAGE);

// 	// Mandatory flag for BPF_MAP_TYPE_SK_STORAGE (https://docs.kernel.org/bpf/map_sk_storage.html)
// 	__uint(map_flags, BPF_F_NO_PREALLOC);

// 	// Regular key and values
// 	__type(key, int);
// 	// __type(value, struct bpf_tcp_sock);
// 	__type(value, int);
// } trackedConnections SEC(".maps");

// For TCP_INFO socket option, from tcp.h
#define TCPI_OPT_TIMESTAMPS	1
#define TCPI_OPT_SACK		2
#define TCPI_OPT_WSCALE		4
#define TCPI_OPT_ECN		8 /* ECN was negociated at TCP session init */
#define TCPI_OPT_ECN_SEEN	16 /* we received at least one packet with ECT */
#define TCPI_OPT_SYN_DATA	32 /* SYN-ACK acked data in SYN sent or rcvd */
#define TCPI_OPT_USEC_TS	64 /* usec timestamps */

// From tcp.h: these constants are stripped from vmlinux.h...
#define	TCP_ECN_OK			1
#define	TCP_ECN_QUEUE_CWR	2
#define	TCP_ECN_DEMAND_CWR	4
#define	TCP_ECN_SEEN		8

/*
 * The kernel's HZ value. Be sure to check [0] and [1] for more information on how
 * libbpf-enabled programs can access these kernel configuration settings. The use
 * of HZ is allowing us to convert kernel jiffies into meaningful (i.e. ms) times.
 * The __weak attribute allows for the loading of the eBPF program even if the value
 * of CONFIG_HZ cannot be determined. In that case, CONFIG_HZ would be set to 0,
 * something we handle in the function converting jiffies to ms.
 *   0: https://nakryiko.com/posts/bpf-core-reference-guide/#kconfig-extern-variables
 *   1: https://www.man7.org/linux/man-pages/man5/proc_config.gz.5.html
 */
extern int CONFIG_HZ __kconfig __weak;

/*
 * In case we cannot read the value of he CONFIG_HZ Kconfig variable, we'll use a default
 * value of 1000, which will (very) likely be the configured value anyway...
 */
#define DEFAULT_HZ 1000L

/*
 * How many ms (i.e. milliseconds) are there in a second? This constant has been
 * pulled from [0] to try and be more kernel-compatible.
 *   0: https://elixir.bootlin.com/linux/v5.14/source/tools/include/linux/time64.h#L5
 */
#define MSEC_PER_SEC 1000L

/*
 * How many us (i.e. microseconds) are there in a second? This constant has been
 * pulled from [0] to try and be more kernel-compatible.
 *   0: https://elixir.bootlin.com/linux/v5.14/source/tools/include/linux/time64.h#L9
 */
#define USEC_PER_SEC 1000000L

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u64);
} bpf_next_dump SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, struct bpf_tcp_sock);
} trackedConnections SEC(".maps");

/*
 * Let's define our own struct tcp_info to get rid of the pesky 1 bit bitfields! They mess
 * up the alignment (I suppose) eBPF enforces. This is a nice homework assignment!
 */
 struct flowd_tcp_info {
	__u8 tcpi_state;
	__u8 tcpi_ca_state;
	__u8 tcpi_retransmits;
	__u8 tcpi_probes;
	__u8 tcpi_backoff;
	__u8 tcpi_options;
	__u8 tcpi_snd_wscale: 4;
	__u8 tcpi_rcv_wscale: 4;
	__u8 tcpi_delivery_rate_app_limited: 1;
	__u8 tcpi_fastopen_client_fail: 2;
	__u32 tcpi_rto;
	__u32 tcpi_ato;
	__u32 tcpi_snd_mss;
	__u32 tcpi_rcv_mss;
	__u32 tcpi_unacked;
	__u32 tcpi_sacked;
	__u32 tcpi_lost;
	__u32 tcpi_retrans;
	__u32 tcpi_fackets;
	__u32 tcpi_last_data_sent;
	__u32 tcpi_last_ack_sent;
	__u32 tcpi_last_data_recv;
	__u32 tcpi_last_ack_recv;
	__u32 tcpi_pmtu;
	__u32 tcpi_rcv_ssthresh;
	__u32 tcpi_rtt;
	__u32 tcpi_rttvar;
	__u32 tcpi_snd_ssthresh;
	__u32 tcpi_snd_cwnd;
	__u32 tcpi_advmss;
	__u32 tcpi_reordering;
	__u32 tcpi_rcv_rtt;
	__u32 tcpi_rcv_space;
	__u32 tcpi_total_retrans;
	__u64 tcpi_pacing_rate;
	__u64 tcpi_max_pacing_rate;
	__u64 tcpi_bytes_acked;
	__u64 tcpi_bytes_received;
	__u32 tcpi_segs_out;
	__u32 tcpi_segs_in;
	__u32 tcpi_notsent_bytes;
	__u32 tcpi_min_rtt;
	__u32 tcpi_data_segs_in;
	__u32 tcpi_data_segs_out;
	__u64 tcpi_delivery_rate;
	__u64 tcpi_busy_time;
	__u64 tcpi_rwnd_limited;
	__u64 tcpi_sndbuf_limited;
	__u32 tcpi_delivered;
	__u32 tcpi_delivered_ce;
	__u64 tcpi_bytes_sent;
	__u64 tcpi_bytes_retrans;
	__u32 tcpi_dsack_dups;
	__u32 tcpi_reord_seen;
	__u32 tcpi_rcv_ooopack;
	__u32 tcpi_snd_wnd;
};

#endif
