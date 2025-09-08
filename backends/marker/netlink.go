//go:build linux && ebpf

package marker

import (
	"fmt"
	"net"
	"slices"

	"log/slog"

	"github.com/cilium/ebpf"
	"github.com/florianl/go-tc"
	"github.com/florianl/go-tc/core"
	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const (
	FILTER_PRIORITY uint32 = 1
	FILTER_HANDLE   uint32 = 1

	// Constant TCA_BPF_FLAG_ACT_DIRECT enables direct action mode
	// for eBPF classifiers. Pulled from include/uapi/linux/pkt_cls.h.
	// See tc-bpf(8) for information on the direct-action mode.
	TCA_BPF_FLAG_ACT_DIRECT uint32 = 1 << 0
)

type NetlinkClient struct {
	// conn is a connection to the rtnetlink subsystem
	conn *tc.Tc

	// qdiscs contains the interface names for the interfaces where a clsact
	// qdisc has been created
	qdiscs []string

	// filters contains the interface names for the interfaces where an eBPF
	// filter has been added
	filters []string
}

// Gets a new connection to the kernel's rtnetlink subsystem. Beware that
// the returned connection should be closed to avoid leaking fds.
func NewNetlinkClient() (*NetlinkClient, error) {
	// Open a netlink/tc connection to the kernel to manage qdiscs
	tcnl, err := tc.Open(&tc.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not open rtnetlink socket: %w", err)
	}

	// For enhanced error messages from the kernel, it is recommended to set
	// option `NETLINK_EXT_ACK`, which is supported since 4.12 kernel. If not
	// supported, `unix.ENOPROTOOPT` is returned.
	if err := tcnl.SetOption(netlink.ExtendedAcknowledge, true); err != nil {
		slog.Warn("could not set option ExtendedAcknowledge", "err", err)
	}

	return &NetlinkClient{conn: tcnl}, nil
}

func (nl *NetlinkClient) Close(tearQdiscs bool) error {
	if tearQdiscs {
		for _, iface := range nl.qdiscs {
			if err := nl.RemoveFilterQdisc(iface); err != nil {
				slog.Warn("error removing qdisc", "interface", iface, "err", err)
			}
		}
	}

	return nl.conn.Close()
}

// Kernels 6.6+ bring support for the TC eBPF Fast Path (tcx) [0] which adds support for
// attaching programs with links [1]. Given we're targetting the 5.14 kernel series that's
// shipped with AlmaLinux we're 'stuck' with interacting with netlink to:
//
//   1. Create a qdisc on which to attach our eBPF program.
//   2. Attach the eBPF program.
//
// This also means we have to deal with all the associated housekeeping... The good news is
// libraries abstracting much of this process away are available. The reference implementation
// is of course provided by libbpf. We'll simply extract the netlink messages of interest and
// replay them to avoid having to include libbpf as a dependency.
//
// Now, github.com/vishvananda/netlink is probably the most widely used netlink implementation in
// Go out there. However, the use of its low-level library has shown to be a bit challenging
// when trying to craft lower level messages following struct definitions set forth in rtnetlink(7).
// Luckily for us, we can leverage github.com/florianl/go-tc and the lower level github.com/mdlayher/netlink
// on which it's built to gain access to a thin wrapper around raw netlink messages.
//
// This file bundles up several calls in such a way that flowd-go can manage qdiscs and attached eBPF filters
// with ease and total control.
// 0: https://docs.ebpf.io/linux/syscall/BPF_LINK_CREATE/#tcx
// 1: https://docs.ebpf.io/linux/syscall/BPF_LINK_CREATE/

// Create a qdisc/clsact object that will be attached to the ingress part
// of the networking interface. One can check how libbpf handles the creation
// of the qdisc only to find it's being handled in exactly the same way
// here:
//
//	 Type: RTM_NEWQDISC -- Add a new qdisc; rtnetlink(7)
//	Flags: NLM_F_CREATE -- Create object if it doesn't already exist; netlink(7)
//	         NLM_F_EXCL -- Don't replace if the object already exists; netlink(7)
//	           NLMF_ACK -- Request for an acknowledgement on success; netlink(7)
//
// The accompanying `struct tcmsg` (rtnetlink(7)) is populated as seen in the
// initialisation of the qdisc struct below.
func craftQdiscDescription(interfaceName string) (tc.Object, error) {
	devID, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return tc.Object{}, fmt.Errorf("could not get interface id: %w", err)
	}

	return tc.Object{
		Msg: tc.Msg{
			// Not really important, likely ignored...
			Family: unix.AF_UNSPEC,

			// The integer identifying the interface on which to attach the qdisc.
			Ifindex: uint32(devID.Index),

			// libbpf populates the handle with `req->tc.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);`.
			// Diving into include/uapi/linux/pkt_sched.h for kernel v5.14 we can see how macro
			// TC_H_MAKE is defined as:
			//
			//   #define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK)
			//
			// and so, when invoked in libbpf it expands to:
			//
			//   0xFFFFFFF1 & 0xFFFF0000 | 0 & 0x0000FFFF = 0xFFFF0000
			//
			// This is the same value that'll be returned by the following call to core.BuildHandle,
			// so this is equivalent to what libbpf is doing.
			Handle: core.BuildHandle(tc.HandleRoot, 0x0000),

			// libbpf initialises this field with TC_H_CLSACT which is defined as TC_H_INGRESS in
			// the kernel; making this initialisation equivalent too!
			Parent: tc.HandleIngress,
			Info:   0,
		},

		// Just like libbpf, specify and additional attribute asking for a clsact qdisc which will
		// allow us to attach filters (i.e. eBPF programs) on the egress path as well as on the
		// ingress path. Be sure to check https://docs.cilium.io/en/latest/reference-guides/bpf/progtypes/#tc-traffic-control
		// for more info on this qdisc type.
		Attribute: tc.Attribute{
			Kind: "clsact",
		},
	}, nil
}

func craftFilterDescription(interfaceName string, progFd *uint32, egress bool) (tc.Object, error) {
	devID, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return tc.Object{}, fmt.Errorf("could not get interface id: %w", err)
	}

	flags := TCA_BPF_FLAG_ACT_DIRECT
	name := "markerHandle"

	return tc.Object{
		Msg: tc.Msg{
			Family:  unix.AF_UNSPEC,
			Ifindex: uint32(devID.Index),

			// Up to now we've been using 1 as the handle. This value seems to be qdisc-related,
			// but we aren't sure of all its implications... Libbpf's default value is 0 though...
			Handle: FILTER_HANDLE,

			// Choose the qdisc path to attach the filter to
			Parent: core.BuildHandle(tc.HandleRoot, func() uint32 {
				if egress {
					return tc.HandleMinEgress
				}
				return tc.HandleMinIngress
			}()),

			// According to the libbpf implementation, it seems the priority is encoded in this
			// info field. We've been running with a priority of 1. Note how the lower 16 bits
			// should end up with the value 0x300 (i.e. unix.ETH_P_ALL) in network (big endian)
			// byte order. The BuildHandle function mimics the TC_H_MAKE macro defined in
			// include/uapi/linux/pkt_sched.h.
			Info: core.BuildHandle(FILTER_PRIORITY, (unix.ETH_P_ALL&0xFF)<<8|(unix.ETH_P_ALL&0xFF00)>>8),
		},
		Attribute: tc.Attribute{
			Kind: "bpf",
			BPF: &tc.Bpf{
				FD:    progFd,
				Flags: &flags,
				Name:  &name,
			},
		},
	}, nil
}

func (nl *NetlinkClient) RemoveFilterQdisc(interfaceName string) error {
	// Craft the qdisc description for the interface
	qdisc, err := craftQdiscDescription(interfaceName)
	if err != nil {
		return fmt.Errorf("error crafting the qdisc description: %w", err)
	}

	// When deleting the qdisc, the applied filter will also be gone
	if err := nl.conn.Qdisc().Delete(&qdisc); err != nil {
		return err
	}

	// Remove the qdisc from our list if present
	if i := slices.Index(nl.qdiscs, interfaceName); i >= 0 {
		nl.qdiscs[i] = nl.qdiscs[len(nl.qdiscs)-1]
		nl.qdiscs = nl.qdiscs[:len(nl.qdiscs)-1]
	}

	return nil
}

func (nl *NetlinkClient) CreateFilterQdisc(interfaceName string) error {
	// Craft the qdisc description for the interface
	qdisc, err := craftQdiscDescription(interfaceName)
	if err != nil {
		return fmt.Errorf("error crafting the qdisc description: %w", err)
	}

	// This call will take care of crafting the correct netlink message header by including
	// the NLM_F_ACK and NLM_F_REQUEST flags as well as the RTM_NEWQDISC message type.
	if err := nl.conn.Qdisc().Add(&qdisc); err != nil {
		return fmt.Errorf("could not assign clsact to qdisc %q: %w", interfaceName, err)
	}

	// If the interface's not being tracked, add it
	if slices.Index(nl.qdiscs, interfaceName) == -1 {
		nl.qdiscs = append(nl.qdiscs, interfaceName)
	}

	return nil
}

func (nl *NetlinkClient) AttachEbpfProgram(interfaceName string, prog *ebpf.Program, egress bool) error {
	fd := uint32(prog.FD())
	filterDescr, err := craftFilterDescription(interfaceName, &fd, egress)
	if err != nil {
		return fmt.Errorf("error crafting filter description: %w", err)
	}

	// This call will take care of crafting the correct netlink message header by including
	// the NLM_F_ACK and NLM_F_REQUEST flags as well as the RTM_NEWTFILTER message type.
	if err := nl.conn.Filter().Add(&filterDescr); err != nil {
		return fmt.Errorf("could not attach filter for eBPF program: %v", err)
	}

	// If the interface's not being tracked, add it
	if slices.Index(nl.filters, interfaceName) == -1 {
		nl.filters = append(nl.filters, interfaceName)
	}

	return nil
}
