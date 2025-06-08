//go:build linux && cgo

package netlink

import "github.com/vishvananda/netlink"

var (
	inetDiagMap = map[uint16]string{
		netlink.INET_DIAG_NONE:            "INET_DIAG_NONE",
		netlink.INET_DIAG_MEMINFO:         "INET_DIAG_MEMINFO",
		netlink.INET_DIAG_INFO:            "INET_DIAG_INFO",
		netlink.INET_DIAG_VEGASINFO:       "INET_DIAG_VEGASINFO",
		netlink.INET_DIAG_CONG:            "INET_DIAG_CONG",
		netlink.INET_DIAG_TOS:             "INET_DIAG_TOS",
		netlink.INET_DIAG_TCLASS:          "INET_DIAG_TCLASS",
		netlink.INET_DIAG_SKMEMINFO:       "INET_DIAG_SKMEMINFO",
		netlink.INET_DIAG_SHUTDOWN:        "INET_DIAG_SHUTDOWN",
		netlink.INET_DIAG_DCTCPINFO:       "INET_DIAG_DCTCPINFO",
		netlink.INET_DIAG_PROTOCOL:        "INET_DIAG_PROTOCOL",
		netlink.INET_DIAG_SKV6ONLY:        "INET_DIAG_SKV6ONLY",
		netlink.INET_DIAG_LOCALS:          "INET_DIAG_LOCALS",
		netlink.INET_DIAG_PEERS:           "INET_DIAG_PEERS",
		netlink.INET_DIAG_PAD:             "INET_DIAG_PAD",
		netlink.INET_DIAG_MARK:            "INET_DIAG_MARK",
		netlink.INET_DIAG_BBRINFO:         "INET_DIAG_BBRINFO",
		netlink.INET_DIAG_CLASS_ID:        "INET_DIAG_CLASS_ID",
		netlink.INET_DIAG_MD5SIG:          "INET_DIAG_MD5SIG",
		netlink.INET_DIAG_ULP_INFO:        "INET_DIAG_ULP_INFO",
		netlink.INET_DIAG_SK_BPF_STORAGES: "INET_DIAG_SK_BPF_STORAGES",
		netlink.INET_DIAG_CGROUP_ID:       "INET_DIAG_CGROUP_ID",
		netlink.INET_DIAG_SOCKOPT:         "INET_DIAG_SOCKOPT",
		netlink.INET_DIAG_MAX:             "INET_DIAG_MAX",
	}
)
