//go:build linux && ebpf

package marker

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"math/rand"

	"github.com/cilium/ebpf"
	glowdTypes "github.com/scitags/flowd-go/types"
)

// Note ports are 32 bits because the struct (and its eBPF counterpart)
// are 8 bytes aligned given the internal uint64s!
type FlowFourTuple struct {
	IPv6Hi  uint64
	IPv6Lo  uint64
	DstPort uint32
	SrcPort uint32
}

type MarkerBackend struct {
	Config

	coll *ebpf.Collection
	nl   *NetlinkClient
	rGen *rand.Rand
}

func NewMarkerBackend(c *Config) (*MarkerBackend, error) {
	b := MarkerBackend{Config: *c}
	return &b, nil
}

func (b *MarkerBackend) String() string {
	return "marker"
}

func (b *MarkerBackend) Init() error {
	slog.Debug("initialising the marker backend")

	// If we need to discover interfaces with public IPv6 addresses simply
	// pull the rug form underneath the configuration.
	if b.DiscoverInterfaces {
		if len(b.TargetInterfaces) != 0 {
			slog.Warn("specified target interfaces will be overridden", "originalTargetInterfaces", b.TargetInterfaces)
		}

		targetInterfaces, err := discoverInterfaces()
		if err != nil {
			return fmt.Errorf("couldn't discover target interfaces: %w", err)
		}
		b.TargetInterfaces = targetInterfaces
	}

	nl, err := NewNetlinkClient()
	if err != nil {
		return fmt.Errorf("error opening the netlink client: %w", err)
	}
	b.nl = nl

	var prog []byte
	if b.ProgramPath != "" {
		slog.Debug("loading the provided eBPF program", "path", b.ProgramPath)
		prog, err = os.ReadFile(b.ProgramPath)
		if err != nil {
			return fmt.Errorf("error reading user provided program: %w", err)
		}
	} else {
		prog, err = chooseProgram(b.MarkingStrategy, b.MatchAll, b.DebugMode)
		if err != nil {
			return fmt.Errorf("error choosing an embedded eBPF program: %w", err)
		}
	}

	// Time to load the program into the kernel
	coll, err := loadProg(prog)
	if err != nil {
		return fmt.Errorf("error loading the eBPF program: %w", err)
	}
	b.coll = coll

	// Time to create the qdiscs and attach the program.
	for _, iface := range b.TargetInterfaces {
		if err := b.nl.CreateFilterQdisc(iface); err != nil {
			b.Cleanup()
			return fmt.Errorf("error creating the clsact qdisc for interface %q: %w", iface, err)
		}

		if err := b.nl.AttachEbpfProgram(iface, coll.Programs[PROG_NAME], true); err != nil {
			b.Cleanup()
			return fmt.Errorf("error attaching the eBPF program to %q: %w", iface, err)
		}
	}

	// Initialise the random number generator
	slog.Debug("initialising the random number generator")
	b.rGen = rand.New(rand.NewSource(time.Now().UnixNano()))

	return nil
}

func (b *MarkerBackend) Run(done <-chan struct{}, inChan <-chan glowdTypes.FlowID) {
	slog.Debug("running the marker backend")

	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID", "flowID", flowID)

			if flowID.Family != glowdTypes.IPv6 {
				slog.Debug("ignoring IPv4 flow")
				continue
			}

			rawDstIPHi, rawDstIPLo := extractHalves(flowID.Dst.IP)
			flowHash := FlowFourTuple{
				IPv6Hi:  rawDstIPHi,
				IPv6Lo:  rawDstIPLo,
				DstPort: uint32(flowID.Dst.Port),
				SrcPort: uint32(flowID.Src.Port),
			}

			switch flowID.State {
			case glowdTypes.START:
				flowTag := b.genFlowTag(flowID.Experiment, flowID.Activity)

				if err := b.coll.Maps[MAP_NAME].Update(flowHash, flowTag, ebpf.UpdateAny); err != nil {
					slog.Error("error inserting map value", "err", err, "flowHash", flowHash, "flowTag", flowTag)
					continue
				}
				slog.Debug("inserted map value", "flowHash", flowHash, "flowTag", flowTag)

				for t, fc := range flowID.FlowInfoChans {
					if fc == nil {
						continue
					}
					go func() {
						for fi := range fc {
							slog.Debug("got flow info", "fi.Cong", fi.Cong, "t", t)
						}
					}()
				}
			case glowdTypes.END:
				if err := b.coll.Maps[MAP_NAME].Delete(flowHash); err != nil {
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

func (b *MarkerBackend) Cleanup() error {
	slog.Debug("cleaning up the marker backend")

	// Remove all the qdiscs and filters
	b.nl.Close(b.RemoveQdisc)

	// Unload the eBPF program
	b.coll.Close()

	return nil
}
