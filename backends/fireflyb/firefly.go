package fireflyb

import (
	"fmt"
	"hash/maphash"
	"log/slog"
	"net"
	"unsafe"

	"github.com/scitags/flowd-go/enrichment/skops"
	glowdTypes "github.com/scitags/flowd-go/types"
)

var (
	Defaults = map[string]interface{}{
		"fireflyDestinationPort": 10514,
		"prependSyslog":          true,
		"addNetlinkContext":      true,
		"addBPFContext":          false,
		"sendToCollector":        false,
		"collectorAddress":       "127.0.0.1",
		"collectorPort":          10514,
		"pollNetlink":            false,
		"pollBPF":                false,
		"netlinkPollingInterval": 5000,
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

	PollBPF                bool `json:"pollBPF"`
	NetlinkPollingInterval int  `json:"netlinkPollingInterval"`
	PollNetlink            bool `json:"pollNetlink"`

	ebpfEnricher *skops.EbpfEnricher

	tcpInfoChan chan skops.TcpInfo

	collectorConn net.Conn

	hashGen maphash.Hash

	ongoingConnections *connectionCache
}

func (b *FireflyBackend) String() string {
	return "Firefly"
}

// Just implement the glowd.Backend interface
func (b *FireflyBackend) Init() error {
	slog.Debug("initialising the firefly backend")

	slog.Debug("initialising the ongoing connections map")
	b.ongoingConnections = NewConnectionCache(100)

	slog.Debug("initialising the hash generator")
	b.hashGen = maphash.Hash{}

	if b.SendToCollector {
		conn, err := net.Dial("udp", parseCollectorAddress(b.CollectorAddress, b.CollectorPort))
		if err != nil {
			return fmt.Errorf("couldn't initialize UDP socket: %w", err)
		}

		b.collectorConn = conn
	}

	if b.PollBPF || b.AddBPFContext {
		slog.Debug("initialising the eBPF enricher")
		enricher, err := skops.NewEnricher()
		if err != nil {
			slog.Warn("couldn't get an eBPF enricher, running without it", "err", err)
		} else {
			b.ebpfEnricher = enricher
		}
	}

	return nil
}

func (b *FireflyBackend) dispatchTCPStats() {
	for tcpInfo := range b.tcpInfoChan {
		slog.Debug("tcpInfo",
			"src", tcpInfo.SrcPort, "dst", tcpInfo.DstPort,
			"sentMBytes", tcpInfo.BytesSent/(1024*1024),
			"rawCwnd", tcpInfo.SndCwnd,
			"mss", tcpInfo.SndMss,
			"cwnd", tcpInfo.SndCwnd*tcpInfo.SndMss/1024,
			"state", tcpInfo.State,
			"newState", tcpInfo.NewState,
			"caAlg", tcpInfo.CaAlg,
			"caState", tcpInfo.CaState,
		)
	}
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan glowdTypes.FlowID) {
	slog.Debug("running the firefly backend")

	if b.PollBPF {
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

			if b.PollBPF {
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

			slog.Debug("sending the firefly...")
			if err := b.sendFirefly(flowID); err != nil {
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
