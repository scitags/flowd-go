# Gathering TCP information with eBPF
This directory contains the implementation of an eBPF-based solution capable of dumping TCP-level statistics from ongoing connections.
The key enabler is the [`BPF_PROG_TYPE_SOCK_OPS`][sockops-prog] eBPF program type. The documentation goes into much more detail, but
put simply it'll be invoked for every RTT and connection state change in a connection. This allows both for a *polling* approach where
we acquire data every RTT (or with a fixed interval to avoid overwhelming the user space program) or an *interrupt* approach where data
is acquired upon connection state changes. Given most of the struct members are accumulators instead of snapshots it's usually good
enough to simply capture the latest state of the connection and be done with it.

## High-level architecture
The context for `BPF_PROG_TYPE_SOCK_OPS` programs is provided by a `struct bpf_sock_ops *`. Through a call to `bpf_skc_to_tcp_sock` (see
`bpf-helpers(7)`) we can get a hold of a `struct tcp_sock *` which is the key here: that's the kernel's representation of a TCP connection!

Now we just need to be careful and leverage `BPF_CORE_READ_INTO` and other related macros to make accesses to the kernel's memory safe.
Besides, these accesses are relocatable in the sense that they're portable across kernel versions thanks to CO:RE's magic.

The eBPF program will simply populate a purposefully defined struct (including subtleties as esoteric as padding and so on) which is then
made available to user space. The sending of information to user space hinges on a [`BPF_MAP_TYPE_RINGBUF`][ringbuf] which offers great
semantics for transferring "large" amounts of data across the kernel boundary. Auxiliary maps are also used to define what connections to
gather information from and to efficiently store time accumulators when running in a polling mode.

The attachment of the program is a bit unconventional in the sense that it attaches to a `cgroup(7)`. Only sockets belonging to this cgroup
are considered by the eBPF program. This offers a nice performance gain in a cgroup-aware configuration as we can just be sensitive to
our target program's sockets if it's running within its own cgroup.

## Comparison with netlink
The `netlink(7)` subsystem is the classical way of gathering this type of information and it's used by tools such as `ss(8)`. If you don't
believe us, try running it through `strace(1)`: we did that to implement our netlink based information gathering!

Anyway, the "bad" thing with netlink is that the information it gathers is fixed and frozen for a particular kernel. What's worse, the
gathered information might change across kernel versions which would make flowd-go brittler than it is! Calls into netlink's API can
provide source and destination addresses and ports to filter the returned information. Diving through the kernel's code shows how the
addresses are silently ignored. The eBPF approach allows us to filter based on this criteria too, so we do have even more granularity
should it be needed. Related to the eBPF's program's attachment, we see how netlink is not aware of any resource sharing mechanisms such
as cgroups. This means it "looks through" every ongoing TCP connection in the kernel. This could pose a performance penalty on systems
with large numbers of concurrent connections.

When it comes to Go's side of things, we find how the netlink parsing logic is simply (and blindly) parsing a netlink message as a large
data blob. This is exactly the same approach we take on our eBPF program, the main difference being we define **both** the structure
and the accompanying parsing logic: nobody will pull the rug from under us!

However, the largest difference might be how netlink only supports a polling-based approach whereas eBPF can work both in a polling and
interrupt mode. This difference grants the eBPF strategy a much better scalability if polling is deemed as a non-viable alternative.

## Validation of acquired data
In order to validate the data we're acquiring through eBPF is correct we have prepared a demonstrator leveraging `iperf3(1)` to
generate controlled, stable and controllable traffic flows. Our tests basically compare the data obtained both with netlink and
eBPF together with the "actual" data provided by `iperf3(1)` itself. The data points are stored as JSON files which are then
parsed by small programs living under `utils/` to generate informative graphs. In order to gather data one has to:

1. Compile the test program with `make test`.
1. Run the program with `sudo ./test -test.run TestGatherFirefly`.
1. In another shell launch `iperf3` with an invocation such as (refer to the manpage for details):

        iperf3 -c <iperf3-server> --cport 2345 --time 180 -p 5777 -i 1 -J | tee iperf3.json

1. Stop the running program with `^C`.
1. Run the plotting utilities to generate the graphs.

Please bear in mind the test program (implemented in `ebpf_test.go`) leverages some hardcoded delays. If the flow is `180 seconds` long
as in the example the timeout should be a bit larger (say, `190`) so that the program can be started before the iperf3 flow. We hope
to provide a less manual interface at some point in the future, but... who knows?

<!-- REFs -->
[sockops-prog]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SOCK_OPS/
[ringbuf]: https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_RINGBUF/
