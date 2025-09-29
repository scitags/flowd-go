package perfsonar

import (
	"log/slog"
	"net"

	"github.com/scitags/flowd-go/types"
)

type PerfsonarPlugin struct {
	Config
}

func NewPerfsonarPlugin(c *Config) (*PerfsonarPlugin, error) {
	p := PerfsonarPlugin{Config: *c}
	return &p, nil
}

func (p *PerfsonarPlugin) String() string {
	return "perfSONAR"
}

func (p *PerfsonarPlugin) Init() error {
	slog.Debug("initialising the perfSONAR plugin")
	return nil
}

func (p *PerfsonarPlugin) Run(done <-chan struct{}, outChan chan<- types.FlowID) {
	slog.Debug("running the perfSONAR plugin")

	/*
	 * We just need to trigger marking once, so we'll do it with dummy addresses.
	 * The key idea is the source and destination ports MUST BE 0: that means
	 * every IPv6 datagram will be marked. That is, source and destination port
	 * 0 disables checks within the eBPF program.
	 */
	slog.Debug("kicking off packet marking")
	outChan <- types.FlowID{
		State:      types.START,
		Family:     types.IPv6,
		Src:        types.IPPort{IP: net.ParseIP("::"), Port: 0},
		Dst:        types.IPPort{IP: net.ParseIP("::"), Port: 0},
		Experiment: uint32(p.ExperimentId),
		Activity:   uint32(p.ActivityId),
	}

	// Simply block until the done channel is closed so that we can exit
	<-done

	slog.Debug("cleanly exiting the perfSONAR plugin")
}

func (p *PerfsonarPlugin) Cleanup() error {
	slog.Debug("cleaning up the perfSONAR plugin")
	return nil
}
