//go:build !linux

package netlink

import (
	"time"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/types"
)

type NetlinkEnricher struct {
}

func NewEnricher(pollingInterval uint64) (*NetlinkEnricher, error) { return nil, nil }

func (e NetlinkEnricher) String() string {
	return "netlink enricher stub"
}

func (e *NetlinkEnricher) Run(done <-chan struct{}) {}
func (e *NetlinkEnricher) WatchFlow(spec enrichment.FlowSpec) (*enrichment.Poller, error) {
	return nil, nil
}
func (e *NetlinkEnricher) ForgetFlow(flowID types.FlowID) (time.Time, bool) { return nil, nil }
func (e *NetlinkEnricher) Cleanup() error                                   { return nil }
