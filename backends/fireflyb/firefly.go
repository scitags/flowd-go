package fireflyb

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
	"github.com/scitags/flowd-go/types"
)

type FireflyBackend struct {
	Config

	collectorConn net.Conn
	enrichers     map[types.Flavour]enrichment.Enricher
}

func (b *FireflyBackend) String() string {
	return "Firefly"
}

func NewFireflyBackend(c *Config) (*FireflyBackend, error) {
	b := FireflyBackend{Config: *c}
	return &b, nil
}

// Just implement the glowd.Backend interface
func (b *FireflyBackend) Init() error {
	slog.Debug("initialising the firefly backend")

	if b.SendToCollector {
		conn, err := net.Dial("udp", parseCollectorAddress(b.CollectorAddress, b.CollectorPort))
		if err != nil {
			return fmt.Errorf("couldn't initialize UDP socket: %w", err)
		}

		b.collectorConn = conn
	}

	if b.PeriodicFireflies {
		slog.Debug("setting up enrichers")
		b.enrichers = make(map[types.Flavour]enrichment.Enricher)

		if b.SkOps != nil {
			slog.Debug("initialising the eBPF enricher")

			enricher, err := skops.NewEnricher(b.SkOps)
			if err != nil {
				return fmt.Errorf("couldn't get an eBPF enricher: %w", err)
			}

			b.enrichers[types.Ebpf] = enricher
		}

		if b.Netlink != nil {
			slog.Debug("initiallising the netlink enricher")

			enricher, err := netlink.NewEnricher(b.Netlink)
			if err != nil {
				return fmt.Errorf("couldn't get a netlink enricher: %w", err)
			}

			b.enrichers[types.Netlink] = enricher
		}
	}

	return nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan types.FlowID) {
	slog.Debug("running the firefly backend")

	doneChans := make([]chan struct{}, len(b.enrichers))
	for _, v := range b.enrichers {
		doneChan := make(chan struct{})
		go v.Run(doneChan)
		doneChans = append(doneChans, doneChan)
	}

	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID", "flowID.Src", flowID.Src, "flowID.Dst", flowID.Dst)

			// Insert the times before doing anything else
			switch flowID.State {
			case types.START:
				flowID.StartTs = time.Now().UTC()
				b.PeriodicFFs(flowID)

			case types.END:
				flowID.EndTs = time.Now().UTC()

				startTs := b.RemoveFlow(flowID)
				slog.Debug("adding start ts", "startTs", startTs)
				flowID.StartTs = startTs
			default:
				slog.Warn("received flowID with wrong state", "state", flowID.State)
			}

			// Send START and END FFs
			ff := types.NewFirefly(flowID, nil, nil)
			payload, err := ff.Payload(b.PrependSyslog)
			if err != nil {
				slog.Error("error building the firefly", "err", err)
				continue
			}

			slog.Debug("sending the firefly...")
			if err := b.sendFirefly(flowID, payload); err != nil {
				slog.Error("error sending the firefly", "err", err)
			}
		case <-done:
			slog.Debug("cleanly exiting the firefly backend")
			return
		}
	}
}

func (b *FireflyBackend) Cleanup() error {
	slog.Debug("cleaning up the firefly backend")

	var err error = nil
	if b.SendToCollector {
		if e := b.collectorConn.Close(); e != nil {
			err = fmt.Errorf("error closing UDP socket: %w", e)
		}
	}

	for i, v := range b.enrichers {
		if e := v.Cleanup(); e != nil {
			err = errors.Join(err, fmt.Errorf("error closing enricher %d: %w", i, e))
		}
	}

	return err
}
