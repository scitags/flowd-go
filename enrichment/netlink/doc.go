// Package netlink implements primitives communicating with the kernel's
// netlink subsystem. Please bear in mind a large portion of this package's
// contents have been plundered form the great github.com/m-lab/tcp-info.
//
// This package leverages the sock_diag(7) netlink subsystem to acquire
// socket-level information. Be sure to check netlink(7) for further
// information on netlink as a whole.
//
// Bear in mind we're targetting the v5.14 kernel series given it's the
// one shipped with AlmaLinux by default. Given the careful design practices
// in the kernel, backwards compatibility should be maintained even if
// running on newer kernels, but this is not explicitly tested.
//
// The main logic driving TCP diag requests on the kernel's netlink subsystem
// can be found on [0], which in turn calls into inet_diag_dump_icsk [1].
// Port numbers set to 0 will not be applied as a filter. That is, if you
// desire to retrieve all the sockets simply pass 0, 0 to both the source
// and destination ports. Note that even if filtering on IP addresses is
// not available, IP information is contained in responses. Not only that,
// from a conceptual point of view at the L4 level ports are univocal IDs in the
// sense that the {src,dst}Port tuple will be unique no matter what the actual
// IPs are... The entry point for NLM_F_DUMP requests seems to be [0]. However,
// the amount of callbacks can get tricky...
//
// 0: https://elixir.bootlin.com/linux/v6.12.4/source/net/ipv4/tcp_diag.c#L181
//
// 1: https://elixir.bootlin.com/linux/v6.12.4/source/net/ipv4/inet_diag.c#L1019
//
// 3: https://elixir.bootlin.com/linux/v6.12.4/source/net/core/rtnetlink.c#L6597
package netlink
