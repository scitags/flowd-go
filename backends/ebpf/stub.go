//go:build darwin || !cgo

package ebpf

import (
	glowd "github.com/scitags/flowd-go"
)

var Defaults = map[string]interface{}{}

type EbpfBackend struct {
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

func (b *EbpfBackend) Run(<-chan struct{}, <-chan glowd.FlowID) {
}

func (b *EbpfBackend) Cleanup() error {
	return nil
}
