//go:build !ebpf

package iperf3

import (
	"log/slog"

	"github.com/scitags/flowd-go/types"
)

type Iperf3Plugin struct {
	Config
}

func NewIperf3Plugin(c *Config) (*Iperf3Plugin, error) {
	return nil, nil
}

func (p *Iperf3Plugin) String() string {
	return "iperf3"
}

func (p *Iperf3Plugin) Init() error {
	slog.Debug("initialising the iperf3 plugin")
	return nil
}

func (p *Iperf3Plugin) closeBuffer(done <-chan struct{}) {
}

func (p *Iperf3Plugin) Run(done <-chan struct{}, outChan chan<- types.FlowID) {
}

func (p *Iperf3Plugin) Cleanup() error {
	return nil
}
