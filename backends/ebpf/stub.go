//go:build darwin || !cgo

package ebpf

import (
	glowd "github.com/scitags/flowd-go"
)

type EbpfBackend struct {
}

type EbpfBackendConf struct {
}

func (c *EbpfBackendConf) UnmarshalJSON(data []byte) error {
	*c = EbpfBackendConf{}
	return nil
}

func New(conf *EbpfBackendConf) *EbpfBackend {
	return &EbpfBackend{}
}

// Just implement the glowd.Backend interface
func (b *EbpfBackend) Init() error {
	return nil
}

func (b *EbpfBackend) Run(<-chan struct{}, <-chan glowd.FlowID) {
}

func (b *EbpfBackend) Cleanup() error {
	return nil
}
