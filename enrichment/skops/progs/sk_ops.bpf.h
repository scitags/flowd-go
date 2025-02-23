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

// From tcp.h
#define	TCP_ECN_OK			1
#define	TCP_ECN_QUEUE_CWR	2
#define	TCP_ECN_DEMAND_CWR	4
#define	TCP_ECN_SEEN		8

// See https://nakryiko.com/posts/bpf-core-reference-guide/#kconfig-extern-variables
extern int CONFIG_HZ __kconfig __weak;

// See https://elixir.bootlin.com/linux/v5.14/source/tools/include/linux/time64.h#L5
#define MSEC_PER_SEC	1000L

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

#endif
