#ifndef __WATCHER_INC__
#define __WATCHER_INC__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Protocol families from socket.h
#define AF_INET 2
#define AF_INET6 10

// TCP States
#define TCP_INVALID     0
#define TCP_ESTABLISHED 1
#define TCP_SYN_SENT    2
#define TCP_SYN_RECV    3
#define TCP_FIN_WAIT1   4
#define TCP_FIN_WAIT2   5
#define TCP_TIME_WAIT   6
#define TCP_CLOSE       7
#define TCP_CLOSE_WAIT  8
#define TCP_LAST_ACK    9
#define TCP_LISTEN      10
#define TCP_CLOSING     11

const volatile unsigned long long MIN_SRC_PORT = 0;
const volatile unsigned long long MAX_SRC_PORT = 0;
const volatile unsigned long long MIN_DST_PORT = 0;
const volatile unsigned long long MAX_DST_PORT = 0;

struct flowSpec {
	__u64 family;

	__u64 sIpHi;
	__u64 sIpLo;
	__u32 sPort;

	__u64 dIpHi;
	__u64 dIpLo;
	__u32 dPort;

	__u64 state;
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024 /* 256 KB */);
} flowNots SEC(".maps");

#endif
