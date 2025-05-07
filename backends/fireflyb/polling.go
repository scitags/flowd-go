package fireflyb

import (
	"log/slog"
	"time"

	"github.com/scitags/flowd-go/enrichment/netlink"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) pollNetlinkStatus(done chan *netlink.InetDiagTCPInfoResp, flowID glowdTypes.FlowID) {
	slog.Debug("entering netlink polling goroutine", "flowID", flowID)
	var lastNetlinkReply *netlink.InetDiagTCPInfoResp
	for {
		select {
		case <-done:
			slog.Debug("quitting netlink polling goroutine", "flowID", flowID)
			done <- lastNetlinkReply
			return
		case <-time.Tick(time.Millisecond * time.Duration(b.NetlinkPollingInterval)):
			nlInfo, err := b.addNetlinkContext(uint8(flowID.Family), flowID.Src.Port, flowID.Dst.Port)
			if err != nil {
				slog.Warn("error polling netlink...", "err", err)
				continue
			}
			slog.Debug("partial netlink info", "family",
				flowID.Family, "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port,
				"congestionAlgorithm", nlInfo.Cong.Algorithm,
				"state", nlInfo.TCPInfo.State,
				"bytesSent", nlInfo.TCPInfo.Bytes_sent,
				"bytesReceived", nlInfo.TCPInfo.Bytes_received,
				"bytesACKd", int(nlInfo.TCPInfo.Bytes_acked),
				"bytesRetrans", nlInfo.TCPInfo.Bytes_retrans,
			)

			// Get a hold of the last piece of info we acquired
			lastNetlinkReply = nlInfo
		}
	}
}

// func (b *FireflyBackend) pollBPFStatus(done chan *netlink.InetDiagTCPInfoResp, flowID glowdTypes.FlowID) {
// 	slog.Debug("entering eBPF polling goroutine", "flowID", flowID)
// 	var lastNetlinkReply *netlink.InetDiagTCPInfoResp
// 	for {
// 		select {
// 		case <-done:
// 			slog.Debug("quitting eBPF polling goroutine", "flowID", flowID)
// 			done <- lastNetlinkReply
// 			return
// 		case <-b.ebpfEnricher:
// 			nlInfo, err := b.addNetlinkContext(uint8(flowID.Family), flowID.Src.Port, flowID.Dst.Port)
// 			if err != nil {
// 				slog.Warn("error polling netlink...", "err", err)
// 				continue
// 			}
// 			slog.Debug("partial netlink info", "family",
// 				flowID.Family, "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port,
// 				"congestionAlgorithm", nlInfo.Cong.Algorithm,
// 				"state", nlInfo.TCPInfo.State,
// 				"bytesSent", nlInfo.TCPInfo.Bytes_sent,
// 				"bytesReceived", nlInfo.TCPInfo.Bytes_received,
// 				"bytesACKd", int(nlInfo.TCPInfo.Bytes_acked),
// 				"bytesRetrans", nlInfo.TCPInfo.Bytes_retrans,
// 			)

// 			// Get a hold of the last piece of info we acquired
// 			lastNetlinkReply = nlInfo
// 		}
// 	}
// }
