package main

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
	"github.com/scitags/flowd-go/types"
)

func createEnrichers(c *Config) (map[types.Flavour]enrichment.Enricher, error) {
	enrichers := map[types.Flavour]enrichment.Enricher{}
	if c.Enrichers == nil {
		return enrichers, nil
	}

	if c.Enrichers.SkOps != nil {
		slog.Debug("initialising the skOps enricher")

		enricher, err := skops.NewEnricher(c.Enrichers.SkOps)
		if err != nil {
			return nil, fmt.Errorf("couldn't get an eBPF enricher: %w", err)
		}

		enrichers[types.Ebpf] = enricher
	}

	if c.Enrichers.Netlink != nil {
		slog.Debug("initialising the netlink enricher")

		enricher, err := netlink.NewEnricher(c.Enrichers.Netlink)
		if err != nil {
			return nil, fmt.Errorf("couldn't get a netlink enricher: %w", err)
		}

		enrichers[types.Netlink] = enricher
	}

	return enrichers, nil
}

func cleanupEnrichers(ee map[types.Flavour]enrichment.Enricher) {
	for t, e := range ee {
		slog.Debug("cleaning enricher", "type", t)
		if err := e.Cleanup(); err != nil {
			slog.Warn("error cleaning up enricher", "type", t, "err", err)
		}
	}
}

// broadcastEnrichment broadcasts enrichment information to the various available
// backends. Information is received through the several sourceChannels and is
// then dispatched to the dispatchChannels. This allows for the independent treatment
// of the flow information by the various backends. Given the concurrent nature of
// the design, it's paramount that:
//
//  1. Once a source channel is closed **every** associated dispatch channel (i.e. with the
//     same types.Flavour) should be closed as well. The source channel is then set to nil
//     to signal no more data will be received on that channel anymore.
//
//  2. Every backend should read its associated dispatch channel even if it is not
//     leveraging the information for anything. This greatly simplifies setting up the
//     broadcast infrastructure, but requires that we be careful to avoid blocking when
//     sending information on each dispatch channel.
//
// Be careful: this function's a big-time offender when it comes to deadlocks!
func broadcastEnrichment(sourceChannels map[types.Flavour]chan *types.FlowInfo, dispatchChannels map[types.Flavour][]chan *types.FlowInfo) {
	slog.Debug("starting enrichment broadcast")
	for {
		select {
		case fi, ok := <-sourceChannels[types.Ebpf]:
			slog.Debug("got skOps flow information to broadcast")
			if !ok {
				// Make the chan always block
				slog.Debug("stopping skOps flow information broadcast")
				sourceChannels[types.Ebpf] = nil
				for i, c := range dispatchChannels[types.Ebpf] {
					slog.Debug("closing broadcast skOps flow information channel", "i", i)
					close(c)
				}
				break
			}
			for i, c := range dispatchChannels[types.Ebpf] {
				slog.Debug("broadcasting skOps flow information", "i", i)
				c <- fi
			}

		case fi, ok := <-sourceChannels[types.Netlink]:
			slog.Debug("got netlink flow information to broadcast")
			if !ok {
				// Make the chan always block
				slog.Debug("stopping netlink flow information broadcast")
				sourceChannels[types.Netlink] = nil
				for i, c := range dispatchChannels[types.Netlink] {
					slog.Debug("closing broadcast netlink flow information channel", "i", i)
					close(c)
				}
				break
			}
			for i, c := range dispatchChannels[types.Netlink] {
				slog.Debug("broadcasting netlink flow information", "i", i)
				c <- fi
			}
		}

		// Bail when both channels are closed
		if sourceChannels[types.Ebpf] == nil && sourceChannels[types.Netlink] == nil {
			slog.Debug("stopping enrichment broadcast")
			return
		}
	}
}
