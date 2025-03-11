//go:build linux && cgo

package ebpf

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"

	bpf "github.com/aquasecurity/libbpfgo"
)

func (b *EbpfBackend) chooseBPFProgram() []byte {
	if b.ProgramPath != "" {
		content, err := os.ReadFile(b.ProgramPath)
		if err != nil {
			slog.Warn(
				"couldn't read the eBPF program from disk, defaulting to flowLabel-based marking", "err", err)
			return flowLabelBPFProg
		}
		slog.Debug("loading the provided eBPF program", "path", b.ProgramPath)
		return content
	}

	slog.Debug("loading an embedded BPF program", "markingStrategy", b.MarkingStrategy, "debugMode", b.DebugMode)
	switch b.MarkingStrategy {
	case FlowLabelMarking:
		if b.DebugMode {
			return flowLabelDebugBPFProg
		}
		return flowLabelBPFProg
	case FlowLabelMatchAll:
		if b.DebugMode {
			return flowLabelMatchAllDebugBPFProg
		}
		return flowLabelMatchAllBPFProg
	case HopByHopHeaderMarking:
		if b.DebugMode {
			return hopByHopHeaderDebugBPFProg
		}
		return hopByHopHeaderBPFProg
	case HopByHopDestHeadersMarking:
		if b.DebugMode {
			return hopByHopDestHeaderDebugBPFProg
		}
		return hopByHopDestHeaderBPFProg
	default:
		slog.Warn("wrong marking strategy, defaulting to flowLabel-based (non-debug) marking",
			"markingStrategy", b.MarkingStrategy)
		return flowLabelBPFProg
	}
}

func (b *EbpfBackend) setupLogging() {
	slog.Debug("setting up logging")
	libbpfLogLevel := bpf.LibbpfWarnLevel
	if slog.Default().Handler().Enabled(context.TODO(), slog.LevelDebug) {
		libbpfLogLevel = logLevelTranslation[slog.LevelDebug]
	} else if slog.Default().Handler().Enabled(context.TODO(), slog.LevelInfo) {
		libbpfLogLevel = logLevelTranslation[slog.LevelInfo]
	}

	bpf.SetLoggerCbs(bpf.Callbacks{
		Log: func(level int, msg string) {
			if level <= libbpfLogLevel {
				// Remove the trailing newline coming from C-land...
				for _, line := range strings.Split(msg, "\n") {
					if line != "" {
						slog.Info(line)
					}
				}

			}
		},
	})
}

func extractHalves(ip net.IP) (uint64, uint64) {
	var addrHi uint64
	var addrLo uint64

	rawIP := []byte(ip)

	// net.IPs are internally represented as a 16-element []byte with
	// the last element being the LSByte and the first the MSByte.
	if len(rawIP) != 16 {
		return 0, 0
	}

	for i := 0; i < 8; i++ {
		addrHi |= uint64(rawIP[i]) << (8 * (8 - (1 + i)))
		addrLo |= uint64(rawIP[i+8]) << (8 * (8 - (1 + i)))
	}

	return addrHi, addrLo
}

// Implementation of Section 1.2 of https://docs.google.com/document/d/1x9JsZ7iTj44Ta06IHdkwpv5Q2u4U2QGLWnUeN2Zf5ts/edit?usp=sharing
func (b *EbpfBackend) genFlowTag(experimentId, activityId uint32) uint32 {
	// We'll slice this number up to get our needed 5 random bits
	rNum := b.rGen.Uint32()

	// The experimentId is supposed to be 9 bits long and reversed. That's why we have a hardcoded 9 here!
	var experimentIdRev uint32 = 0
	for i := 0; i < 9; i++ {
		experimentIdRev |= (experimentId & (0x1 << i) >> i) << ((9 - 1) - i)
	}

	var flowTag uint32 = (rNum & (0x3 << 18)) | ((experimentIdRev & 0x1FF) << 9) | (rNum & (0x1 << 8)) | ((activityId & 0x3F) << 2) | (rNum & 0x3)

	slog.Debug("genFlowTag", "experimentId", fmt.Sprintf("%b", experimentId), "experimentIdRev", fmt.Sprintf("%b", experimentIdRev),
		"activityId", fmt.Sprintf("%b", activityId), "flowTag", fmt.Sprintf("%b", flowTag))

	return flowTag
}

func (b *EbpfBackend) initTCHook(targetInterfaceIndex int, targetInterface string, progFd int) error {
	// Create the TC Hook on which to place the eBPF program
	slog.Debug("initialising a TC hook", "targetInterface", targetInterface)
	hook := b.module.TcHookInit()
	if err := hook.SetInterfaceByName(targetInterface); err != nil {
		return fmt.Errorf("failed to set TC hook on interface %s: %w", targetInterface, err)
	}

	// Place the hook in the packet egress chain
	slog.Debug("creating the hook", "targetInterface", targetInterface)
	hook.SetAttachPoint(bpf.BPFTcEgress)
	if err := hook.Create(); err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			slog.Debug("error creating the tc hook", "targetInterface", targetInterface, "err", err)
		}
	}

	// Prepare the options for the hook
	// https://elixir.bootlin.com/linux/v6.8.4/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L26
	tcOpts := bpf.TcOpts{
		ProgFd:   progFd,
		Handle:   TC_HANDLE,
		Priority: TC_PRIORITY,
		Flags:    bpf.BpfTcFReplace, // Let's replace the hooked program no matter what!
	}

	// Attach the program!
	slog.Debug("attaching the TC hook", "targetInterface", targetInterface)
	b.hooksCreated[targetInterfaceIndex] = true
	if err := hook.Attach(&tcOpts); err != nil {
		if errors.Is(err, syscall.EEXIST) {
			slog.Warn("looks like flowd-go didn't clean up after itself: the eBPF hook's still there!")

			b.hooksCreated[targetInterfaceIndex] = false

			// TODO: In case somebody else is using the backing qdisc we should maybe
			// TODO: not delete it: that's just bad manners! See [0].
			// TODO:   0: https://github.com/libbpf/libbpf-bootstrap/blob/master/examples/c/tc.c
			// b.RemoveQdisc = false
		} else {
			return fmt.Errorf("couldn't attach the eBPF hook: %w", err)
		}
	}

	// Test we can get the program back to check everything's okay
	slog.Debug("preflight eBPF checks", "targetInterface", targetInterface)
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	tcOpts.Flags = 0
	slog.Debug("tcOpts before querying", "targetInterface", targetInterface, "tcOpts", tcOpts)
	if err := hook.Query(&tcOpts); err != nil {
		return fmt.Errorf("error querying for the ebpf program: %w", err)
	}
	slog.Debug("tcOpts after querying", "targetInterface", targetInterface, "tcOpts", tcOpts)
	if tcOpts.Handle != 1 {
		return fmt.Errorf("recovered handle %d is different than expected (i.e. 1)", tcOpts.Handle)
	}
	b.hooks[targetInterfaceIndex] = hook

	// Get a hold of the tcOpts once all the operations are done: it can be implicitly changed as
	// we're passing the struct (i.e. b) by reference!
	b.tcOpts[targetInterfaceIndex] = tcOpts

	return nil
}

func RemoveTCHook(targetInterface string, removeQdisc bool) error {
	// Create an empty module: we need it to call TcHookInit through it...
	dummyModule := bpf.Module{}

	// Create the TC Hook on which to place the eBPF program
	slog.Debug("initialising the hook")
	hook := dummyModule.TcHookInit()
	if err := hook.SetInterfaceByName(targetInterface); err != nil {
		return fmt.Errorf("failed to set TC hook on interface %s: %w", targetInterface, err)
	}
	hook.SetAttachPoint(bpf.BPFTcEgress)

	// Prepare the options for the hook
	// See __bpf_tc_detach on https://github.com/libbpf/libbpf/blob/master/src/netlink.c
	var tcOpts bpf.TcOpts = bpf.TcOpts{
		ProgFd:   0, // This member should be 0, otherwise libbpf will complain!
		ProgId:   0, // This member should be 0, otherwise libbpf will complain!
		Flags:    0, // This member should be 0, otherwise libbpf will complain!
		Handle:   1,
		Priority: 1,
	}

	slog.Debug("detaching the tc hook")
	if err := hook.Detach(&tcOpts); err != nil {
		slog.Error("error detaching the ebpf hook", "err", err)
	}

	if removeQdisc {
		slog.Debug("removing the backing qdisc")
		// Explicitly ask for the backing QDisc to be destroyed.
		// See https://patchwork.kernel.org/project/netdevbpf/patch/20210428162553.719588-3-memxor@gmail.com/
		hook.SetAttachPoint(bpf.BPFTcEgress | bpf.BPFTcIngress)
	}

	slog.Debug("destroying the tc hook")
	if err := hook.Destroy(); err != nil {
		slog.Warn("error destroying the hook", "err", err)
	}

	return nil
}
