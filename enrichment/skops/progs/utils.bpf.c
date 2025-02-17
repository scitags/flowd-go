// // Extract the lower 64 bits of an IPv6 address
// static __always_inline __u64 ipv6AddrLo(__u32* ipv6Addr) {
// 	__u64 lo = bpf_htonl(addr.in6_u.u6_addr32[2]);
// 	return lo << 32 | bpf_htonl(addr.in6_u.u6_addr32[3]);
// }

// // Extract the upper 64 bits of an IPv6 address
// static __always_inline __u64 ipv6AddrHi(__u32* ipv6Addr) {
// 	__u64 hi = bpf_htonl(addr.in6_u.u6_addr32[0]);
// 	return hi << 32 | bpf_htonl(addr.in6_u.u6_addr32[1]);
// }
