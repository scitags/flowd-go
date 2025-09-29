//go:build !linux || !ebpf

package marker

import (
	"github.com/scitags/flowd-go/types"
)

// TODO: consider a shared definition
type MarkerBackend struct {
	Config
}

func NewMarkerBackend(c *Config) (*MarkerBackend, error) {
	return nil, nil
}

func (b *MarkerBackend) String() string {
	return "eBPF stub"
}

// Just implement the glowd.Backend interface
func (b *MarkerBackend) Init() error {
	return nil
}

func (b *MarkerBackend) Run(<-chan struct{}, <-chan types.FlowID) {
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
