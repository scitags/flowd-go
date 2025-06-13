package fireflyb

import (
	"fmt"
	"hash/maphash"
	"log/slog"
	"net"
	"time"
	"unsafe"

	"github.com/scitags/flowd-go/enrichment/skops"
	glowdTypes "github.com/scitags/flowd-go/types"
)

var (
	Defaults = map[string]interface{}{
		"fireflyDestinationPort": 10514,
		"prependSyslog":          true,

		"sendToCollector":  false,
		"collectorAddress": "127.0.0.1",
		"collectorPort":    10514,

		"periodicFireflies": false,
		"period":            1000,

		"addNetlinkContext": true,
		"addBPFContext":     false,

		"enrichmentVerbosity": "lean",
	}
)

type FireflyBackend struct {
	FireflyDestinationPort uint16 `json:"fireflyDestinationPort"`
	PrependSyslog          bool   `json:"prependSyslog"`

	SendToCollector  bool   `json:"sendToCollector"`
	CollectorAddress string `json:"collectorAddress"`
	CollectorPort    int    `json:"collectorPort"`

	AddNetlinkContext bool `json:"addNetlinkContext"`
	AddBPFContext     bool `json:"addBPFContext"`

	PeriodicFireflies bool `json:"periodicFireflies"`
	Period            int  `json:"period"`

	EnrichmentVerbosity string `json:"enrichmentVerbosity"`

	ebpfEnricher *skops.EbpfEnricher

	tcpInfoChan chan skops.TcpInfo

	collectorConn net.Conn

	hashGen maphash.Hash

	ongoingNetlinkConnections *connectionCache
	ongoingEbpfConnections    *connectionCache
}

func (b *FireflyBackend) String() string {
	return "Firefly"
}

// Just implement the glowd.Backend interface
func (b *FireflyBackend) Init() error {
	slog.Debug("initialising the firefly backend")

	slog.Debug("initialising the ongoing connection maps")
	b.ongoingNetlinkConnections = NewConnectionCache(100)
	// b.ongoingEbpfConnections = NewEbpfConnectionCache(100)
	b.ongoingEbpfConnections = NewConnectionCache(100)

	slog.Debug("initialising the hash generator")
	b.hashGen = maphash.Hash{}

	if b.SendToCollector {
		conn, err := net.Dial("udp", parseCollectorAddress(b.CollectorAddress, b.CollectorPort))
		if err != nil {
			return fmt.Errorf("couldn't initialize UDP socket: %w", err)
		}

		b.collectorConn = conn
	}

	if b.PeriodicFireflies || b.AddBPFContext {
		slog.Debug("initialising the eBPF enricher")
		enricher, err := skops.NewEnricher(uint64(b.Period) * glowdTypes.NS_PER_MS)
		if err != nil {
			slog.Warn("couldn't get an eBPF enricher, running without it", "err", err)
		} else {
			b.ebpfEnricher = enricher
		}
	}

	return nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan glowdTypes.FlowID) {
	slog.Debug("running the firefly backend")

	if b.PeriodicFireflies && b.ebpfEnricher != nil {
		b.tcpInfoChan = make(chan skops.TcpInfo)
		go b.ebpfEnricher.Run(done, b.tcpInfoChan)
		go b.dispatchTCPStats()
	}

	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID")

			if b.PeriodicFireflies && b.ebpfEnricher != nil {
				fSpec := skops.FlowSpec{
					DstPort: uint32(flowID.Dst.Port),
					SrcPort: uint32(flowID.Src.Port),
				}
				flowSpecPtr := unsafe.Pointer(&fSpec)

				if flowID.State == glowdTypes.START {
					var dummy byte = 1
					dummyPtr := unsafe.Pointer(&dummy)
					if err := b.ebpfEnricher.FlowMap.Update(flowSpecPtr, dummyPtr); err != nil {
						slog.Error("error inserting value into flow map: %w, stats will not be collected", err)
					}
				} else if flowID.State == glowdTypes.END {
					if err := b.ebpfEnricher.FlowMap.DeleteKey(flowSpecPtr); err != nil {
						slog.Error("error deleting key from flow map: %w", err)
					}
				} else {
					slog.Warn("wrong state for the flow ID", "state", flowID.State)
				}
			}

			// Insert the times before doing anything else
			switch flowID.State {
			case glowdTypes.START:
				flowID.StartTs = time.Now().UTC()
			case glowdTypes.END:
				flowID.EndTs = time.Now().UTC()

				auxFlowID := flowID
				// Zero out the addresses to not take them into account when hashing
				auxFlowID.Src.IP = net.IP{}
				auxFlowID.Dst.IP = net.IP{}

				flowHash := b.hashFlowID(auxFlowID)
				entry, ok := b.ongoingEbpfConnections.Get(flowHash)
				if !ok {
					slog.Warn("non-existent cache entry", "hash", flowHash)
					break
				}
				slog.Debug("adding start ts", "startTs", entry.startTs)

				flowID.StartTs = entry.startTs
			default:
				slog.Warn("received flowID with wrong state", "state", flowID.State)
			}

			if b.PeriodicFireflies {
				if b.AddNetlinkContext {
					b.enrichNetlink(flowID)
				}
				if b.AddBPFContext {
					b.enrichEbpf(flowID)
				}
			}

			payload, err := b.buildFirefly(flowID, nil, nil)
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

	if b.SendToCollector {
		if err := b.collectorConn.Close(); err != nil {
			return fmt.Errorf("error closing UDP socket: %w", err)
		}
	}

	if b.tcpInfoChan != nil {
		slog.Debug("cleaning closing the TCP Info eBPF channel")
		close(b.tcpInfoChan)
	}

	return nil
}
