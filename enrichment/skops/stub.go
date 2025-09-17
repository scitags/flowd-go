//go:build !linux

package skops

import (
	"time"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/types"
)

type EbpfEnricher struct{}

func NewEnricher(pollingInterval uint64) (*EbpfEnricher, error) { return nil, nil }

func (e *EbpfEnricher) String() string {
	return "eBPF enricher stub"
}

func (e *EbpfEnricher) Run(done <-chan struct{}) {}
func (e *EbpfEnricher) WatchFlow(flowID types.FlowID) (*enrichment.Poller, error) {
	return nil, nil
}
func (e *EbpfEnricher) ForgetFlow(flowID types.FlowID) (time.Time, bool) { return time.Time{}, nil }
func (e *EbpfEnricher) Cleanup() error                                   { return nil }
