package fireflyb

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"

	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) buildFirefly(flowID glowdTypes.FlowID, nlInfo, ebpfInfo *glowdTypes.Enrichment) ([]byte, error) {
	localFirefly := glowdTypes.Firefly{}

	localFirefly.Version = glowdTypes.FIREFLY_VERSION

	localFirefly.FlowLifecycle.State = flowID.State.String()

	localFirefly.PopulateTimeStamps(flowID)

	localFirefly.FlowID.AFI = flowID.Family.String()
	localFirefly.FlowID.SrcIP = flowID.Src.IP.String()
	localFirefly.FlowID.DstIP = flowID.Dst.IP.String()
	localFirefly.FlowID.Protocol = flowID.Protocol.String()
	localFirefly.FlowID.SrcPort = flowID.Src.Port
	localFirefly.FlowID.DstPort = flowID.Dst.Port

	localFirefly.Context.ExperimentID = flowID.Experiment
	localFirefly.Context.ActivityID = flowID.Activity
	localFirefly.Context.Application = flowID.Application

	localFirefly.Netlink = nlInfo
	localFirefly.EbpfTcpInfo = ebpfInfo

	// TODO: If src IP address is private, get one through STUN!

	payload, err := json.Marshal(localFirefly)
	if err != nil {
		return nil, fmt.Errorf("error marshalling firefly: %w", err)
	}

	if b.PrependSyslog {
		syslogHeader := []byte(fmt.Sprintf(glowdTypes.SYSLOG_HEADER, localFirefly.FlowLifecycle.CurrentTime))
		payload = append(syslogHeader, payload...)
	}

	return payload, nil
}

func (b *FireflyBackend) enrichEbpf(flowID glowdTypes.FlowID) {
	auxFlowID := flowID
	// Zero out the addresses to not take them into account when hashing
	auxFlowID.Src.IP = net.IP{}
	auxFlowID.Dst.IP = net.IP{}

	flowHash := b.hashFlowID(auxFlowID)

	switch flowID.State {
	case glowdTypes.START:
		slog.Debug("beginning ebpf polling")

		slog.Debug("creating ongoing connection", "flowHash", flowHash)
		cacheEntry, ok := b.ongoingEbpfConnections.Insert(flowHash, flowID.StartTs)
		if !ok {
			go b.pollEbpfStatus(cacheEntry.doneChan, flowID)
		} else {
			slog.Warn("an entry for this flowID already existed", "auxFlowID", auxFlowID)
		}
	case glowdTypes.END:
		slog.Debug("eBPF polling is implicitly terminated with the connection state transitions")
	}
}

func (b *FireflyBackend) enrichNetlink(flowID glowdTypes.FlowID) {
	switch flowID.State {
	case glowdTypes.START:

		slog.Debug("beginning netlink polling")
		cacheEntry, ok := b.ongoingNetlinkConnections.Insert(b.hashFlowID(flowID), flowID.StartTs)
		if !ok {
			go b.pollNetlinkStatus(cacheEntry.doneChan, flowID)
		} else {
			slog.Warn("an entry for this flowID already existed", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)
		}

	case glowdTypes.END:

		slog.Debug("ending netlink polling")
		flowHash := b.hashFlowID(flowID)

		_, ok := b.ongoingNetlinkConnections.Get(flowHash)
		if !ok {
			slog.Warn("found no entry in connection cache for this flowID", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)
		}

		slog.Debug("dispatching end signal on done channel", "srcPort", flowID.Src.Port, "dstPort", flowID.Dst.Port)

		b.ongoingNetlinkConnections.Remove(flowHash)
	}
}
