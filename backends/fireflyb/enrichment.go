//go:build linux && cgo

package fireflyb

import (
	"log/slog"
	"net"
	"time"

	"github.com/scitags/flowd-go/enrichment/skops"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) pollNetlinkStatus(done chan []*glowdTypes.Enrichment, flowID glowdTypes.FlowID) {
	slog.Debug("entering netlink polling goroutine", "flowID", flowID)
	netlinkReplies := make([]*glowdTypes.Enrichment, 0, 10)
	for {
		select {
		case <-done:
			slog.Debug("quitting netlink polling goroutine", "flowID", flowID)
			done <- netlinkReplies
			return
		case <-time.Tick(time.Millisecond * time.Duration(b.NetlinkPollingInterval)):
			nlInfo, err := b.addNetlinkContext(uint8(flowID.Family), flowID.Src.Port, flowID.Dst.Port)
			if err != nil {
				slog.Warn("error polling netlink...", "err", err)
				continue
			}

			if nlInfo.TCPInfo != nil && nlInfo.Cong != nil {
				slog.Debug("partial netlink info", "family",
					flowID.Family, "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port,
					"congestionAlgorithm", nlInfo.Cong.Algorithm,
					"state", nlInfo.TCPInfo.State,
					"bytesSent", nlInfo.TCPInfo.Bytes_sent,
					"bytesReceived", nlInfo.TCPInfo.Bytes_received,
					"bytesACKd", int(nlInfo.TCPInfo.Bytes_acked),
					"bytesRetrans", nlInfo.TCPInfo.Bytes_retrans,
				)
			} else {
				slog.Debug("partial netlink info", "nlInfo", nlInfo)
			}

			nlInfo.Verbosity = b.EnrichmentVerbosity

			// Get a hold of the last piece of info we acquired
			netlinkReplies = append(netlinkReplies, nlInfo)
		}
	}
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

		go b.updateEbpfStatus(tcpInfo)
	}
}

func (b *FireflyBackend) updateEbpfStatus(tcpi skops.TcpInfo) {
	flowID := glowdTypes.FlowID{
		Src: glowdTypes.IPPort{
			IP:   net.IP{},
			Port: tcpi.SrcPort,
		},
		Dst: glowdTypes.IPPort{
			IP:   net.IP{},
			Port: tcpi.DstPort,
		},
	}
	flowHash := b.hashFlowID(flowID)

	info := tcpi.ToTCPInfoResp()
	info.Verbosity = b.EnrichmentVerbosity

	slog.Debug("inserting ebpf-gathered TCP info", "flowHash", flowHash)
	b.ongoingEbpfConnections.Insert(flowHash, info)
}
