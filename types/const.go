package types

// All of these constants' names make the linter complain, but we inherited
// them from external C code, so we will keep them as they are...
const (
	TCP_INVALID     State = 0
	TCP_ESTABLISHED State = 1 // or unix.BPF_TCP_ESTABLISHED
	TCP_SYN_SENT    State = 2
	TCP_SYN_RECV    State = 3
	TCP_FIN_WAIT1   State = 4
	TCP_FIN_WAIT2   State = 5
	TCP_TIME_WAIT   State = 6
	TCP_CLOSE       State = 7
	TCP_CLOSE_WAIT  State = 8
	TCP_LAST_ACK    State = 9
	TCP_LISTEN      State = 10 // or unix.BPF_TCP_LISTEN
	TCP_CLOSING     State = 11

	// TCP_ALL_FLAGS includes flag bits for all TCP connection states. It corresponds to TCPF_ALL in some linux code.
	TCP_ALL_FLAGS = 0xFFF

	NS_PER_MS uint64 = 1_000_000

	// Options for the `options` member in `struct tcp_info`. See
	// https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/tcp.h#L166
	// for details.
	TCPI_OPT_TIMESTAMPS uint8 = 1
	TCPI_OPT_SACK       uint8 = 2
	TCPI_OPT_WSCALE     uint8 = 4
	TCPI_OPT_ECN        uint8 = 8  /* ECN was negociated at TCP session init */
	TCPI_OPT_ECN_SEEN   uint8 = 16 /* we received at least one packet with ECT */
	TCPI_OPT_SYN_DATA   uint8 = 32 /* SYN-ACK acked data in SYN sent or rcvd */
)

var (
	stateName = map[State]string{
		TCP_INVALID:     "INVALID",
		TCP_ESTABLISHED: "ESTABLISHED",
		TCP_SYN_SENT:    "SYN_SENT",
		TCP_SYN_RECV:    "SYN_RECV",
		TCP_FIN_WAIT1:   "FIN_WAIT1",
		TCP_FIN_WAIT2:   "FIN_WAIT2",
		TCP_TIME_WAIT:   "TIME_WAIT",
		TCP_CLOSE:       "CLOSE",
		TCP_CLOSE_WAIT:  "CLOSE_WAIT",
		TCP_LAST_ACK:    "LAST_ACK",
		TCP_LISTEN:      "LISTEN",
		TCP_CLOSING:     "CLOSING",
	}

	// Map compatibleStateNames allows for the lookup of TCP states into
	// names compatible with the legacy flowd implementation. These names
	// have been pulled from [0].
	//
	// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
	compatibleStateNames = map[State]string{
		TCP_INVALID:     "INVALID",
		TCP_ESTABLISHED: "established",
		TCP_SYN_SENT:    "syn-sent",
		TCP_SYN_RECV:    "syn-recv",
		TCP_FIN_WAIT1:   "fin-wait-1",
		TCP_FIN_WAIT2:   "fin-wait-2",
		TCP_TIME_WAIT:   "time-wait",
		TCP_CLOSE:       "unconnected",
		TCP_CLOSE_WAIT:  "close-wait",
		TCP_LAST_ACK:    "last-ack",
		TCP_LISTEN:      "listening",
		TCP_CLOSING:     "closing",
	}
)
