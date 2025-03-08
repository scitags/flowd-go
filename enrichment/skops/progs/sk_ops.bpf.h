#ifndef __SKOPS_INC__
#define __SKOPS_INC__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

/*
 * Specification (i.e. {src,dst} IPv{4,6} {src,dst} port) of a given flow.
 * Note how leveraging __u64's allows us to support both IPv4 and IPv6
 * addresses. For IPv4, the entire IPv4 address will be encoded in the
 * lower 32 bits of ip6Lo.
 */
struct fourTuple {
	__u64 ip6Hi;
	__u64 ip6Lo;
	__u16 dPort;
	__u16 sPort;
};

#ifdef FLOWD_POLL
	/*
	* If we're polling information we can store the last timestamp when we acquired
	* data in the socket itself. See [0] and [1] for an example and more docs!
	*   0: https://github.com/torvalds/linux/blob/76544811c850a1f4c055aa182b513b7a843868ea/samples/bpf/tcp_dumpstats_kern.c
	*   1: https://docs.kernel.org/bpf/map_sk_storage.html
	*/
	struct {
		__uint(type, BPF_MAP_TYPE_SK_STORAGE);
		__uint(map_flags, BPF_F_NO_PREALLOC);
		__type(key, int);
		__type(value, __u64);
	} pollAcc SEC(".maps");

	/*
	 * Poll interval in nanoseconds: we should try to specify this as an extern variable when
	 * loading the program through libbpf with Module.InitGlobalVariable from libbpfgo or
	 * something of the sort!
	 */
	#define INTERVAL 1000000000ULL /* 1 sec */
#endif

/*
 * Map allowing userspace to signal what flows to dump statistics for.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, __u8);
} flowsToFollow SEC(".maps");

/*
 * Ring buffer allowing us to send tcp statistics out. Note the size must be a
 * multiple of the kernel's page size (i.e. 4096 bytes almost always). Check
 * [0, 1, 2].
 *   0: https://nakryiko.com/posts/bpf-ringbuf/
 *   1: https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/ringbuf-output.c
 *   2: https://github.com/anakryiko/bpf-ringbuf-examples/blob/main/src/ringbuf-output.bpf.c
 */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} tcpStats SEC(".maps");

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
 * Instead of passing strings to userspace we'll simply map each congestion
 * algorithm name to an enumerated type. These have been extracted from
 * the list generated with:
 *
 *   $ grep 'struct tcp_congestion_ops' -A 15 net/ipv4/tcp*.c | grep '\.name' | awk '{print $4}'
 *
 * ran from Linux's source on version 5.14.
 */
enum {
	FLOWD_CA_UNK,
	FLOWD_CA_BBR,
	FLOWD_CA_BIC,
	FLOWD_CA_CDG,
	FLOWD_CA_RENO,
	FLOWD_CA_CUBIC,
	FLOWD_CA_DCTCP,
	FLOWD_CA_DCTCP_RENO,
	FLOWD_CA_HIGHSPEED ,
	FLOWD_CA_HTCP,
	FLOWD_CA_HYBLA,
	FLOWD_CA_ILLINOIS,
	FLOWD_CA_LP,
	FLOWD_CA_NV,
	FLOWD_CA_SCALABLE,
	FLOWD_CA_VEGAS,
	FLOWD_CA_VENO,
	FLOWD_CA_WESTWOOD,
	FLOWD_CA_YEAH,
};

/*
 * The size of the __u64 array used for storing the congestion algorithm
 * private information.
 */
#define FLOWD_TCPI_CA_PRIV_SIZE 13

/*
 * The kernel's HZ value. Be sure to check [0] and [1] for more information on how
 * libbpf-enabled programs can access these kernel configuration settings. The use
 * of HZ is allowing us to convert kernel jiffies into meaningful (i.e. ms) times.
 * The __weak attribute allows for the loading of the eBPF program even if the value
 * of CONFIG_HZ cannot be determined. In that case, CONFIG_HZ would be set to 0,
 * something we handle in the function converting jiffies to ms. An example of how
 * to convert jiffies to time values can be seen on [2].
 *   0: https://nakryiko.com/posts/bpf-core-reference-guide/#kconfig-extern-variables
 *   1: https://www.man7.org/linux/man-pages/man5/proc_config.gz.5.html
 *   2: https://nakryiko.com/posts/bpf-portability-and-co-re/
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

/*
 * For some reason this struct isn't defined in vmlinux.h... It's defined in [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_vegas.h#L9
 */
struct vegas {
	u32	beg_snd_nxt;		/* right edge during last RTT */
	u32	beg_snd_una;		/* left edge  during last RTT */
	u32	beg_snd_cwnd;		/* saves the size of the cwnd */
	u8	doing_vegas_now;	/* if true, do vegas for this RTT */
	u16	cntRTT;				/* # of RTTs measured within last RTT */
	u32	minRTT;				/* min of RTTs measured within last RTT (in usec) */
	u32	baseRTT;			/* the min of all Vegas RTT measurements seen (in usec) */
};

/*
 * For some reason this struct isn't defined in vmlinux.h... It's defined in [0].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/net/ipv4/tcp_dctcp.c#L47
 */
struct dctcp {
	u32 old_delivered;
	u32 old_delivered_ce;
	u32 prior_rcv_nxt;
	u32 dctcp_alpha;
	u32 next_seq;
	u32 ce_state;
	u32 loss_cwnd;
};

/*
 * Let's define our own struct tcp_info to get rid of the pesky 1 bit bitfields! They mess
 * up the alignment (I suppose) eBPF enforces. This is a nice homework assignment! Anyway,
 * the original is over at [0]. It's also crucial to talk a bit about the alignment of the
 * structure. On [1] one can find a nice discussion on struct layouts in memory. This
 * document references the SysV ABI [2] which specifies how this alignment will be
 * managed. From a pragmatic perspective, we can just use pahole(1) to take a look
 * at the layout of the compiled *.o file with:
 *
 *   $ pahole sk_ops.o
 *
 * This shows whether padding has been added for alignment or not. We have manually made
 * some members a bit larger to fall within the alignment borders. We even went as far as
 * adding a 'padding' member near the bottom of the struct to align everything correctly.
 * This 'issue' with alignment shows how complex it is to go down to the ABI level and keep
 * things consistent. It goes without saying that any changes made to the following declaration
 * MUST also be made to its Go counterpart. At some point we should look into generating the
 * definition of Go's struct type based on this file's contents with CGo and 'go generate', but
 * it sounds like a considerable time investment to at least get something that's working
 * reliably... A nice piece on structure packing can be found on [3].
 *   0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/tcp.h#L214
 *   1: https://foojay.io/today/hello-ebpf-auto-layouting-structs-7/
 *   2: https://refspecs.linuxbase.org/elf/x86_64-abi-0.99.pdf
 *   3: http://www.catb.org/esr/structure-packing/
 */
 struct flowd_tcp_info {
	__u8 tcpi_state;
	__u8 tcpi_retransmits;
	__u8 tcpi_probes;
	__u8 tcpi_backoff;
	__u8 tcpi_options;
	__u8 tcpi_snd_wscale;
	__u8 tcpi_rcv_wscale;
	__u8 tcpi_delivery_rate_app_limited;
	__u32 tcpi_fastopen_client_fail; /* (we use a __u32 for alignment) */

	__u32 tcpi_rto;
	__u32 tcpi_ato;
	__u32 tcpi_snd_mss;
	__u32 tcpi_rcv_mss;

	__u32 tcpi_unacked;
	__u32 tcpi_sacked;
	__u32 tcpi_lost;
	__u32 tcpi_retrans;
	__u32 tcpi_fackets;

	/* Times */
	__u32 tcpi_last_data_sent;
	__u32 tcpi_last_ack_sent;
	__u32 tcpi_last_data_recv;
	__u32 tcpi_last_ack_recv;

	/* Metrics */
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

	__u64 tcpi_total_retrans; /* We use a __u64 for alignment */

	__u64 tcpi_pacing_rate;
	__u64 tcpi_max_pacing_rate;
	__u64 tcpi_bytes_acked;    /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	__u64 tcpi_bytes_received; /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	__u32 tcpi_segs_out;       /* RFC4898 tcpEStatsPerfSegsOut */
	__u32 tcpi_segs_in;        /* RFC4898 tcpEStatsPerfSegsIn */

	__u32 tcpi_notsent_bytes;
	__u32 tcpi_min_rtt;
	__u32 tcpi_data_segs_in;  /* RFC4898 tcpEStatsDataSegsIn */
	__u32 tcpi_data_segs_out; /* RFC4898 tcpEStatsDataSegsOut */

	__u64 tcpi_delivery_rate;

	__u64 tcpi_busy_time;      /* Time (usec) busy sending data */
	__u64 tcpi_rwnd_limited;   /* Time (usec) limited by receive window */
	__u64 tcpi_sndbuf_limited; /* Time (usec) limited by send buffer */

	__u32 tcpi_delivered;
	__u32 tcpi_delivered_ce;

	__u64 tcpi_bytes_sent;    /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	__u64 tcpi_bytes_retrans; /* RFC4898 tcpEStatsPerfOctetsRetrans */
	__u32 tcpi_dsack_dups;    /* RFC4898 tcpEStatsStackDSACKDups */
	__u32 tcpi_reord_seen;    /* reordering events seen */

	__u32 tcpi_rcv_ooopack;   /* Out-of-order packets received */

	__u32 tcpi_snd_wnd;       /* peer's advertised receive window after scaling (bytes) */

	/* TCP Congestion Algorithm (CA) Info */
	__u16 tcpi_ca_alg;        /* CA algorithm as a FLOW_CA_* enum member (we use a __u16 for alignment) */
	__u16 tcpi_ca_state;      /* (we use a __u16 for alignment) */
	__u32 tcpi_ca_key;
	__u32 tcpi_ca_flags;
	__u32 padding; /* just aligning the data */
	__u64 tcpi_ca_priv[FLOWD_TCPI_CA_PRIV_SIZE];
};

#endif
