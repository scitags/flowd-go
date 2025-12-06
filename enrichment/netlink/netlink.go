//go:build linux

package netlink

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/florianl/go-diag"
	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/types"
)

type NetlinkEnricher struct {
	Config

	conn  *diag.Diag
	cache *enrichment.FlowCache
}

func (e NetlinkEnricher) String() string {
	return "netlink enricher"
}

func (e *NetlinkEnricher) Cleanup() error {
	return e.conn.Close()
}

func NewEnricher(config *Config) (*NetlinkEnricher, error) {
	// open a netlink socket in our namespace
	nl, err := diag.Open(&diag.Config{})
	if err != nil {
		return nil, fmt.Errorf("could not open netlink socket: %w", err)
	}

	if config == nil {
		config = &DefaultConfig
	}

	return &NetlinkEnricher{
		Config: *config,
		conn:   nl,
		cache:  enrichment.NewFlowCache(config.CacheCapacity),
	}, nil
}

// A simple noop to check synchronisation and adhere to the enrichment.Enricher interface
func (e *NetlinkEnricher) Run(done <-chan struct{}) {
	slog.Debug("starting the netlink enricher")
	<-done
	slog.Debug("cleanly stopping the netlink enricher")
}

func (e *NetlinkEnricher) WatchFlow(flowID types.FlowID) (*enrichment.Poller, error) {
	hash := enrichment.HashFlowID(flowID)
	poller, ok := e.cache.Insert(hash, flowID.StartTs)
	if ok {
		slog.Warn("an entry for this flowID already existed", "flowID", flowID)
	}

	go func() {
		slog.Debug("entering polling goroutine", "hash", hash)
		for {
			select {
			case <-poller.DoneChan:
				slog.Debug("cleanly exiting polling goroutine", "hash", hash)
				e.cache.Remove(hash)
				return
			case <-time.Tick(time.Duration(e.Period) * time.Millisecond):
				for _, fi := range e.GetFlowInfo(flowID) {
					poller.DataChan <- &fi
				}
			}
		}
	}()

	return &poller, nil
}

func (e *NetlinkEnricher) ForgetFlow(flowID types.FlowID) (time.Time, bool) {
	hash := enrichment.HashFlowID(flowID)
	slog.Debug("marking flow for removal", "hash", hash)
	return e.cache.MarkForRemoval(hash)
}

func (e *NetlinkEnricher) GetFlowInfo(flowID types.FlowID) []types.FlowInfo {
	res, err := e.conn.NetDump(&diag.NetOption{
		Family:   uint8(flowID.Family),
		Protocol: e.Protocol,
		Ext:      e.Ext,
		State:    e.State,
		ID: diag.SockID{
			// As seen on [0], there are no mentions to r->id.idiag_src or r->id.idiag_dst so it looks like
			// filtering on IP addresses has no effect whatsoever. The same goes for interfaces and cookies.
			// On the other hand, if looking for a single socket these seem to be taken into account [1].
			// 0: https://elixir.bootlin.com/linux/v6.12.4/source/net/ipv4/inet_diag.c#L1019
			// 1: https://elixir.bootlin.com/linux/v6.12.4/source/net/ipv4/inet_diag.c#L519
			SPort: Htons(flowID.Src.Port()),
			DPort: Htons(flowID.Dst.Port()),
		},
	})
	if err != nil {
		slog.Warn("error getting TCP information", "err", err)
		return nil
	}

	if len(res) == 0 {
		slog.Warn("got no netlink information back")
		return nil
	}

	fis := []types.FlowInfo{}

	for _, r := range res {
		fis = append(fis, inetDiagToFlowInfo(r))
	}

	return fis
}
