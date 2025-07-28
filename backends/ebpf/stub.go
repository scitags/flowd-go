//go:build darwin || !cgo

package ebpf

import (
	glowdTypes "github.com/scitags/flowd-go/types"
)

type EbpfBackend struct {
	MarkingStrategy MarkingStrategy
}

type EbpfBackendConf struct {
}

func (b *EbpfBackend) String() string {
	return "eBPF stub"
}

// Just implement the glowd.Backend interface
func (b *EbpfBackend) Init() error {
	return nil
}

func (b *EbpfBackend) Run(<-chan struct{}, <-chan glowdTypes.FlowID) {
}

func (b *EbpfBackend) Cleanup() error {
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
