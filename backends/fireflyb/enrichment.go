//go:build linux && cgo

package fireflyb

import (
	"log/slog"
	"net"
	"time"

	"github.com/scitags/flowd-go/enrichment/skops"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) pollNetlinkStatus(done chan *glowdTypes.Enrichment, flowID glowdTypes.FlowID) {
	slog.Debug("entering netlink polling goroutine", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)

	// Make periodic fireflies have an ongoing state.
	flowID.State = glowdTypes.ONGOING

	// After Go 1.23 this shouldn't be mandatory, but we'll cleanly instantiate and recover the ticker
	// just in case.
	ticker := time.NewTicker(time.Millisecond * time.Duration(b.Period))
	defer ticker.Stop()

	for {
		select {
		case _, ok := <-done:
			if !ok {
				slog.Debug("quitting netlink polling goroutine", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)
				return
			}

		case <-ticker.C:
			nlInfo, err := b.addNetlinkContext(uint8(flowID.Family), flowID.Src.Port, flowID.Dst.Port)
			if err != nil {
				slog.Warn("error polling netlink...", "err", err)
				continue
			}

			slog.Debug("partial netlink info")

			// if nlInfo.TCPInfo != nil && nlInfo.Cong != nil {
			// 	slog.Debug("partial netlink info", "family",
			// 		flowID.Family, "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port,
			// 		"congestionAlgorithm", nlInfo.Cong.Algorithm,
			// 		"state", nlInfo.TCPInfo.State,
			// 		"bytesSent", nlInfo.TCPInfo.Bytes_sent,
			// 		"bytesReceived", nlInfo.TCPInfo.Bytes_received,
			// 		"bytesACKd", int(nlInfo.TCPInfo.Bytes_acked),
			// 		"bytesRetrans", nlInfo.TCPInfo.Bytes_retrans,
			// 	)
			// } else {
			// 	slog.Debug("partial netlink info", "nlInfo", nlInfo)
			// }

			nlInfo.Verbosity = b.EnrichmentVerbosity

			payload, err := b.buildFirefly(flowID, nlInfo, nil)
			if err != nil {
				slog.Error("error building periodic firefly", "err", err)
				continue
			}

			if err := b.sendFirefly(flowID, payload); err != nil {
				slog.Error("error sending periodic firefly", "err", err)
			}
		}
	}
}

func (b *FireflyBackend) dispatchTCPStats() {
	for tcpInfo := range b.tcpInfoChan {
		// slog.Debug("tcpInfo",
		// 	"src", tcpInfo.SrcPort, "dst", tcpInfo.DstPort,
		// 	"sentMBytes", tcpInfo.BytesSent/(1024*1024),
		// 	"rawCwnd", tcpInfo.SndCwnd,
		// 	"mss", tcpInfo.SndMss,
		// 	"cwnd", tcpInfo.SndCwnd*tcpInfo.SndMss/1024,
		// 	"state", tcpInfo.State,
		// 	"newState", tcpInfo.NewState,
		// 	"caAlg", tcpInfo.CaAlg,
		// 	"caState", tcpInfo.CaState,
		// )

		go b.updateEbpfStatus(tcpInfo)
	}
}

func (b *FireflyBackend) pollEbpfStatus(doneChan chan *glowdTypes.Enrichment, flowID glowdTypes.FlowID) {
	slog.Debug("entering ebpf polling goroutine", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)

	// Make periodic fireflies have an ongoing state.
	flowID.State = glowdTypes.ONGOING

	for ebpfSnapshot := range doneChan {
		// if ebpfSnapshot.TCPInfo != nil && ebpfSnapshot.Cong != nil {
		// 	slog.Debug("partial ebpf info", "family",
		// 		flowID.Family, "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port,
		// 		"congestionAlgorithm", ebpfSnapshot.Cong.Algorithm,
		// 		"state", ebpfSnapshot.TCPInfo.State,
		// 		"bytesSent", ebpfSnapshot.TCPInfo.Bytes_sent,
		// 		"bytesReceived", ebpfSnapshot.TCPInfo.Bytes_received,
		// 		"bytesACKd", int(ebpfSnapshot.TCPInfo.Bytes_acked),
		// 		"bytesRetrans", ebpfSnapshot.TCPInfo.Bytes_retrans,
		// 	)
		// } else {
		// 	slog.Debug("partial ebpf info", "ebpfSnapshot", ebpfSnapshot)
		// }

		slog.Debug("partial eBPF info")

		payload, err := b.buildFirefly(flowID, nil, ebpfSnapshot)
		if err != nil {
			slog.Error("error building periodic firefly", "err", err)
			continue
		}

		if err := b.sendFirefly(flowID, payload); err != nil {
			slog.Error("error sending periodic firefly", "err", err)
		}
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
	cacheEntry, ok := b.ongoingEbpfConnections.Get(flowHash)
	if !ok {
		slog.Error("nonexistent channel for flow")
		return
	}

	slog.Debug("current TCP state", "state", tcpi.State, "newState", tcpi.NewState)

	cacheEntry.doneChan <- info

	if tcpi.NewState == skops.CLOSE {
		slog.Debug("shutting down eBPF poller", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)
		b.ongoingEbpfConnections.CloseChan(flowHash)
	}
}
