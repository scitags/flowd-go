package fireflyb

import (
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/scitags/flowd-go/internal/stun"
	"github.com/scitags/flowd-go/types"
)

type FireflyBackend struct {
	Config

	collectorConn net.Conn
	pubIpMap      map[netip.Addr]netip.Addr
}

func (b *FireflyBackend) String() string {
	return "Firefly"
}

func NewFireflyBackend(c *Config) (*FireflyBackend, error) {
	b := FireflyBackend{Config: *c}
	slog.Debug("initialising the firefly backend")

	if b.SendToCollector {
		conn, err := net.Dial("udp", parseCollectorAddress(b.CollectorAddress, b.CollectorPort))
		if err != nil {
			return nil, fmt.Errorf("couldn't initialize UDP socket: %w", err)
		}
		b.collectorConn = conn
	}

	if c.Stun != nil {
		slog.Debug("mapping private addresses to public ones")
		pubIpMap, err := stun.GetPublicAddresses(*c.Stun)
		if err != nil {
			return nil, fmt.Errorf("couldn't resolve private to public addresses: %w", err)
		}
		b.pubIpMap = pubIpMap
	}

	return &b, nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan types.FlowID) {
	slog.Debug("running the firefly backend")

	var usageChan chan types.FlowUsage = nil
	var payload []byte
	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID", "flowID.Src", flowID.Src, "flowID.Dst", flowID.Dst)

			// Rewrite private source IP address
			if len(b.pubIpMap) > 0 {
				pubIp, ok := b.pubIpMap[flowID.Src.Addr()]
				if ok {
					slog.Debug("rewriting private ip", "privIp", flowID.Src.Addr(), "pubIp", pubIp)
					flowID.Src = netip.AddrPortFrom(pubIp, flowID.Src.Port())
				}
			}

			// Insert the times before doing anything else
			switch flowID.State {
			case types.START:
				if b.Enrich {
					for t, fc := range flowID.FlowInfoChans {
						if fc == nil {
							continue
						}

						if b.OnlyEnd {
							usageChan = make(chan types.FlowUsage)
							go b.endEvent(fc, usageChan)
						} else {
							go b.periodicFFs(flowID, t, fc)
						}
					}
				}
				tmp, err := b.buildFirefly(flowID, nil)
				if err != nil {
					slog.Error("error building the firefly", "err", err)
					continue
				}
				payload = tmp

			case types.END:
				var usage *types.FlowUsage = nil
				if usageChan != nil {
					select {
					case fi := <-usageChan:
						slog.Debug("got closing info", "sent", fi.Sent, "received", fi.Received)
						usage = &fi
						break
					case <-time.Tick(time.Duration(30 * time.Second)):
						break
					}
				}
				tmp, err := b.buildFirefly(flowID, usage)
				if err != nil {
					slog.Error("error building the firefly", "err", err)
					continue
				}
				payload = tmp
			default:
				slog.Warn("received flowID with wrong state", "state", flowID.State)
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

func (b *FireflyBackend) buildFirefly(flowID types.FlowID, usage *types.FlowUsage) ([]byte, error) {
	ff := types.NewFirefly(flowID, nil, nil, usage)
	payload, err := ff.Payload(b.PrependSyslog)
	if err != nil {
		return nil, err
	}
	return payload, nil

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
