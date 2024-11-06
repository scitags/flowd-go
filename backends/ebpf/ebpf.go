//go:build linux && cgo

package ebpf

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"math/rand"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pcolladosoto/glowd"
)

// Please note this example has been basically plundered from:
//   https://github.com/libbpf/libbpf-bootstrap/blob/4a567f229efe8fc79ee1a2249569eb6b9c02ad1b/examples/c/tc.c
//   https://github.com/aquasecurity/libbpfgo/blob/282d44353ac28b015afb469d378e9d178afd3304/selftest/tc/main.go

const (
	PROG_NAME string = "marker"
	MAP_NAME  string = "flowLabels"
)

var (
	//go:embed marker.bpf.o
	bpfObj []byte

	configurationTags = map[string]bool{
		"targetinterface": false,
		"removeqdisc":     false,
		"programpath":     false,
	}

	DefaultConf = EbpfBackendConf{
		TargetInterface: "lo",
		RemoveQdisc:     true,
		ProgramPath:     "",
	}
)

type EbpfBackendConf struct {
	TargetInterface string `json:"targetInterface"`
	RemoveQdisc     bool   `json:"removeQdisc"`
	ProgramPath     string `json:"programPath"`
}

// We need an alias to avoid infinite recursion
// in the unmarshalling logic
type AuxEbpfBackendConf EbpfBackendConf

type EbpfBackend struct {
	module  *bpf.Module
	hook    *bpf.TcHook
	flowMap *bpf.BPFMap

	tcOpts bpf.TcOpts

	rGen *rand.Rand

	conf EbpfBackendConf
}

type flowFourTuple struct {
	IPv6Hi  uint64
	IPv6Lo  uint64
	DstPort uint16
	SrcPort uint16
}

func (c *EbpfBackendConf) UnmarshalJSON(data []byte) error {
	tmp := map[string]interface{}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmp map: %w", err)
	}

	for k := range tmp {
		delete(configurationTags, strings.ToLower(k))
	}

	tmpConf := AuxEbpfBackendConf{}
	if err := json.Unmarshal(data, &tmpConf); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmpConf: %w", err)
	}

	for k := range configurationTags {
		switch strings.ToLower(k) {
		case "targetinterface":
			tmpConf.TargetInterface = DefaultConf.TargetInterface
		case "removeqdisc":
			tmpConf.RemoveQdisc = DefaultConf.RemoveQdisc
		case "programpath":
			tmpConf.ProgramPath = DefaultConf.ProgramPath
		default:
			return fmt.Errorf("unknown configuration key %q", k)
		}
	}

	// Store the results!
	*c = EbpfBackendConf(tmpConf)

	return nil
}

func New(conf *EbpfBackendConf) *EbpfBackend {
	if conf == nil {
		return &EbpfBackend{conf: DefaultConf}
	}
	return &EbpfBackend{conf: *conf}
}

func (b *EbpfBackend) Init() error {
	slog.Debug("initialising the ebpf backend")

	// Create the BPF module
	bpfProgram := bpfObj
	if b.conf.ProgramPath != "" {
		content, err := os.ReadFile(b.conf.ProgramPath)
		if err != nil {
			slog.Warn(
				"couldn't read the eBPF program from disk. Defaulting to the embedded one", "err", err)
		} else {
			bpfProgram = content
		}
	} else {
		slog.Debug("loading the embedded BPF program")
	}

	bpfModule, err := bpf.NewModuleFromBuffer(bpfProgram, "glowd")
	// bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		return fmt.Errorf("error creating the BPF module: %w", err)
	}
	b.module = bpfModule

	// Try to load the module's object
	if err := b.module.BPFLoadObject(); err != nil {
		return fmt.Errorf("error loading the BPF object: %w", err)
	}

	// Create the TC Hook on which to place the eBPF program
	b.hook = b.module.TcHookInit()
	if err := b.hook.SetInterfaceByName(b.conf.TargetInterface); err != nil {
		return fmt.Errorf("failed to set TC hook on interface %s: %w", b.conf.TargetInterface, err)
	}

	// Placce the hook in the packet egress chain
	b.hook.SetAttachPoint(bpf.BPFTcEgress)
	if err := b.hook.Create(); err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			slog.Debug("error creating the tc hook", "err", err)
		}
	}

	// Recover the specific program (i.e. function) we'll be attaching
	tcProg, err := b.module.GetProgram(PROG_NAME)
	if tcProg == nil || err != nil {
		return fmt.Errorf("couldn't find the target program %s: %w", PROG_NAME, err)
	}

	// Prepare the options for the hook
	// https://elixir.bootlin.com/linux/v6.8.4/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L26
	var tcOpts bpf.TcOpts
	tcOpts.ProgFd = int(tcProg.FileDescriptor())
	tcOpts.Handle = 1
	tcOpts.Priority = 1

	// Attach the program!
	if err := b.hook.Attach(&tcOpts); err != nil {
		return fmt.Errorf("couldn't attach the ebpf program: %w", err)
	}

	// Get a reference to the map so that we're ready when running
	bpfMap, err := b.module.GetMap(MAP_NAME)
	if err != nil {
		return fmt.Errorf("error getting the ebpf map: %w", err)
	}
	b.flowMap = bpfMap

	// Test we can get the program back to check everything's okay
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	if err := b.hook.Query(&tcOpts); err != nil {
		return fmt.Errorf("error querying for the ebpf program: %w", err)
	}
	if tcOpts.Handle != 1 {
		return fmt.Errorf("recovered handle %d is different than expected (i.e. 1)", tcOpts.Handle)
	}
	// Get a hold of the tcOpts once all the operations are done: it can be implicitly changed as
	// we're passing it by reference!
	b.tcOpts = tcOpts

	// Initialise the random number generator
	b.rGen = rand.New(rand.NewSource(time.Now().UnixNano()))

	return nil
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

func (b *EbpfBackend) Run(done <-chan struct{}, inChan <-chan glowd.FlowID) {
	slog.Debug("running the ebpf backend")

	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID", "flowID", flowID)

			rawDstIPHi, rawDstIPLo := extractHalves(flowID.Dst.IP)
			flowHash := flowFourTuple{
				IPv6Hi:  rawDstIPHi,
				IPv6Lo:  rawDstIPLo,
				DstPort: flowID.Dst.Port,
				SrcPort: flowID.Src.Port,
			}

			slog.Debug("flowID.Dst.IP", "rawDstIP", fmt.Sprintf("%+v", []byte(flowID.Dst.IP)),
				"rawDstIPHi", rawDstIPHi, "rawDstIPLo", rawDstIPLo)

			switch flowID.State {
			case glowd.START:
				flowTag := b.genFlowTag(flowID.Experiment, flowID.Activity)

				flowHashPtr := unsafe.Pointer(&flowHash)
				flowTagPtr := unsafe.Pointer(&flowTag)
				if err := b.flowMap.Update(flowHashPtr, flowTagPtr); err != nil {
					slog.Error("error inserting map value", "err", err, "flowHash", flowHash, "flowTag", flowTag)
					continue
				}
				slog.Debug("inserted map value", "flowHash", flowHash, "flowTag", flowTag)
			case glowd.END:
				flowHashPtr := unsafe.Pointer(&flowHash)
				if err := b.flowMap.DeleteKey(flowHashPtr); err != nil {
					slog.Error("error deleting map key", "err", err, "flowHash", flowHash)
					continue
				}
				slog.Debug("deleted map value", "flowHash", flowHash)
			default:
				slog.Error("wrong flow state made it here", "flowID.State", flowID.State)
			}
		case <-done:
			slog.Debug("cleanly exiting the ebpf backend")
			return
		}
	}
}

func (b *EbpfBackend) Cleanup() error {
	slog.Debug("cleaning up the ebpf backend")

	// This explicit checks aren't really needed; it's simply left here for emphasis!
	if b.hook != nil {
		// Detach the program. Note ProgFd and ProgId must be set to 0 or the detachment
		// won't work...
		localTcOpts := b.tcOpts
		localTcOpts.ProgFd = 0
		localTcOpts.ProgId = 0

		slog.Debug("detaching the tc hook")
		if err := b.hook.Detach(&localTcOpts); err != nil {
			slog.Error("error detaching the ebpf hook", "err", err)
		}

		if b.conf.RemoveQdisc {
			slog.Debug("removing the backing qdisc")
			// Explicitly ask for the backing QDisc to be destroyed.
			// See https://patchwork.kernel.org/project/netdevbpf/patch/20210428162553.719588-3-memxor@gmail.com/
			b.hook.SetAttachPoint(bpf.BPFTcEgress | bpf.BPFTcIngress)
		}
		slog.Debug("destroying the tc hook")
		if err := b.hook.Destroy(); err != nil {
			slog.Warn("error destroying the hook", "err", err)
		}
	}

	// This explicit checks aren't really needed; it's simply left here for emphasis!
	if b.module != nil {
		slog.Debug("closing the eBPF module")
		b.module.Close()
	}

	return nil
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
