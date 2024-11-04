//go:build darwin || !cgo

package ebpf

import "github.com/pcolladosoto/glowd"

type EbpfBackend struct {
}

func New() *EbpfBackend {
	return &EbpfBackend{}
}

// Just implement the glowd.Backend interface
func (b *EbpfBackend) Init() error                              { return nil }
func (b *EbpfBackend) Run(<-chan struct{}, <-chan glowd.FlowID) {}
func (b *EbpfBackend) Cleanup() error                           { return nil }
