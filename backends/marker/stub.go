//go:build !linux || !ebpf

package marker

import (
	glowdTypes "github.com/scitags/flowd-go/types"
)

type MarkingStrategy string

const (
	Label               MarkingStrategy = "label"
	HopByHop                            = "hopByHop"
	Destination                         = "destination"
	HopByHopDestination                 = "hopByHopDestination"

	PROG_NAME string = "marker"
	MAP_NAME  string = "flowLabels"
)

var Defaults = map[string]interface{}{}

// TODO: consider a shared definition
type MarkerBackend struct {
	TargetInterfaces   []string
	DiscoverInterfaces bool
	RemoveQdisc        bool
	ProgramPath        string
	MarkingStrategy    string
	DebugMode          bool
	MatchAll           bool
}

func (b *MarkerBackend) String() string {
	return "eBPF stub"
}

// Just implement the glowd.Backend interface
func (b *MarkerBackend) Init() error {
	return nil
}

func (b *MarkerBackend) Run(<-chan struct{}, <-chan glowdTypes.FlowID) {
}

func (b *MarkerBackend) Cleanup() error {
	return nil
}

// This type definition is needed so that the cmd utils won't
// complain. Should we maybe relocate this definition someplace
// else?
type FlowFourTuple struct {
	IPv6Hi  uint64
	IPv6Lo  uint64
	DstPort uint16
	SrcPort uint16
}
