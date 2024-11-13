// +build ignore

// Enforceable actions. These are defined on include/uapi/linux/if_ether.h
// (i.e. /usr/include/linux/pkt_cls.h). The problem is including linux/pkt_cls.h
// conflicts with the inclusion of vmlinux.h!
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

// The ETH_P_* constants are defined in include/uapi/linux/if_ether.h
// (i.e. /usr/include/linux/if_ether.h). Again, their inclusion conflicts
// with vmlinux.h...
#define ETH_P_IP    0x0800 /* Internet Protocol packet */
#define ETH_P_IPV6  0x86DD /* IPv6 over bluebook */
#define ETH_P_8021Q 0x8100 /* 802.1Q VLAN Extended Header */

// Protocol numbers. Check https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
#define PROTO_IP_ICMP   0x01
#define PROTO_TCP       0x06
#define PROTO_UDP       0x11
#define PROTO_IPV6_ICMP 0x3A

// Check RFC 2460 Section 4.3 and 4.6:
//   https://www.rfc-editor.org/rfc/rfc2460.html#section-4.3
//   https://www.rfc-editor.org/rfc/rfc2460.html#section-4.6
#define NEXT_HDR_HOP_BY_HOP 0x0
#define NEXT_HDR_DEST_OPTS 60

// The keys for our hash maps. Should we maybe combine the ports into a __u32?
struct fourTuple {
	__u64 ip6Hi;
	__u64 ip6Lo;
	__u16 dPort;
	__u16 sPort;
};

// Let's define our map. Note it'll be included in
// section .maps in the resulting binary.
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 100000);
	__type(key, struct fourTuple);
	__type(value, __u32);
} flowLabels SEC(".maps");

// Hop-by-Hop Extension Header in IPv6. See RFC 2460 Section 4.3
// https://www.rfc-editor.org/rfc/rfc2460.html#section-4.3
struct hopByHopHdr_t {
	__u8 nextHdr;
	__u8 hdrLen;
	__u8 opts[6];
};

struct hopByHopAndDestOptsHdr_t {
	__u8 hbhNextHdr;
	__u8 hbhHdrLen;
	__u8 optsHbH[6];
	__u8 destNextHdr;
	__u8 destHdrLen;
	__u8 optsDest[6];
};
