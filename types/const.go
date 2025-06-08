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
)

var stateName = map[State]string{
	0:  "INVALID",
	1:  "ESTABLISHED",
	2:  "SYN_SENT",
	3:  "SYN_RECV",
	4:  "FIN_WAIT1",
	5:  "FIN_WAIT2",
	6:  "TIME_WAIT",
	7:  "CLOSE",
	8:  "CLOSE_WAIT",
	9:  "LAST_ACK",
	10: "LISTEN",
	11: "CLOSING",
}
