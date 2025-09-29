package fireflyb

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/scitags/flowd-go/types"
)

type FireflyBackend struct {
	Config

	collectorConn net.Conn
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

	return nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan types.FlowID) {
	slog.Debug("running the firefly backend")

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
				if b.Enrich {
					for t, fc := range flowID.FlowInfoChans {
						if fc == nil {
							continue
						}
						go b.periodicFFs(flowID, t, fc)
					}
				}

			case types.END:
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

	return err
}
