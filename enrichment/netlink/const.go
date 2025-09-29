//go:build linux

package netlink

// Constants INET_DIAG_* allow us to populate the Ext bitmap in sock_diag(7) requests
// to signal the information we want to read back. These have been pulled from [0].
// Note that we can only set these 8 options given the Ext field is 1 byte long!
// On [0] one can find several more constants that are considered only when dumping
// all socket statistics instead of when requesting information for a particular one.
//
// 0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/inet_diag.h#L142
const (
	INET_DIAG_NONE uint8 = iota
	INET_DIAG_MEMINFO
	INET_DIAG_INFO
	INET_DIAG_VEGASINFO
	INET_DIAG_CONG
	INET_DIAG_TOS
	INET_DIAG_TCLASS
	INET_DIAG_SKMEMINFO
	INET_DIAG_SHUTDOWN
)
