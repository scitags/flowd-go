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
