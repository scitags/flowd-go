// +build ignore

// Extract the lower 64 bits of an IPv6 address
__u64 ipv6AddrLo(struct in6_addr addr) {
	__u64 lo = bpf_htonl(addr.in6_u.u6_addr32[2]);
	return lo << 32 | bpf_htonl(addr.in6_u.u6_addr32[3]);
}

// Extract the upper 64 bits of an IPv6 address
__u64 ipv6AddrHi(struct in6_addr addr) {
	__u64 hi = bpf_htonl(addr.in6_u.u6_addr32[0]);
	return hi << 32 | bpf_htonl(addr.in6_u.u6_addr32[1]);
}
