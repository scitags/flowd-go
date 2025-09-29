package main

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
	"github.com/scitags/flowd-go/types"
)

type enricherBundle struct {
	enrichment.Enricher
	doneChan chan struct{}
}

func createEnrichers(c *Config) (map[types.Flavour]enricherBundle, error) {
	enrichers := map[types.Flavour]enricherBundle{}
	if c.Enrichers == nil {
		return enrichers, nil
	}

	if c.Enrichers.SkOps != nil {
		slog.Debug("initialising the skOps enricher")

		enricher, err := skops.NewEnricher(&skops.DefaultConfig)
		if err != nil {
			return nil, fmt.Errorf("couldn't get an eBPF enricher: %w", err)
		}

		doneChan := make(chan struct{})
		go enricher.Run(doneChan)

		enrichers[types.Ebpf] = enricherBundle{enricher, doneChan}
	}

	if c.Enrichers.Netlink != nil {
		slog.Debug("initialising the netlink enricher")

		enricher, err := netlink.NewEnricher(&netlink.DefaultConfig)
		if err != nil {
			return nil, fmt.Errorf("couldn't get a netlink enricher: %w", err)
		}

		doneChan := make(chan struct{})
		go enricher.Run(doneChan)

		enrichers[types.Netlink] = enricherBundle{enricher, doneChan}
	}

	return enrichers, nil
}

func cleanupEnrichers(ee map[types.Flavour]enricherBundle) {
	for t, e := range ee {
		slog.Debug("cleaning enricher", "type", t)
		if err := e.Cleanup(); err != nil {
			slog.Warn("error cleaning up enricher", "type", t, "err", err)
		}
	}
}

func broadcastEnrichment(sourceChannels map[types.Flavour]chan *types.FlowInfo, dispatchChannels map[types.Flavour][]chan *types.FlowInfo) {
	for {
		select {
		case fi, ok := <-sourceChannels[types.Ebpf]:
			if !ok {
				// Make the chan always block
				sourceChannels[types.Ebpf] = nil
				for _, c := range dispatchChannels[types.Ebpf] {
					close(c)
				}
				break
			}
			for _, c := range dispatchChannels[types.Ebpf] {
				c <- fi
			}

		case fi, ok := <-sourceChannels[types.Netlink]:
			if !ok {
				// Make the chan always block
				sourceChannels[types.Netlink] = nil
				for _, c := range dispatchChannels[types.Netlink] {
					close(c)
				}
				break
			}
			for _, c := range dispatchChannels[types.Netlink] {
				c <- fi
			}
		}

		// Bail when both channels are closed
		if sourceChannels[types.Ebpf] == nil && sourceChannels[types.Netlink] == nil {
			return
		}
	}
}
