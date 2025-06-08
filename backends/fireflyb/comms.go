package fireflyb

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	glowdTypes "github.com/scitags/flowd-go/types"
)

// TODO: Sending with the vanilla API's great, but we might need to look into
// TODO: some lower level handling of the sockets. Options include leveraging
// TODO: the AF_PACKET (packet(7)) family or even the AF_XDP [0,1,2] family.
// TODO: the latter might be a bit too much though given how no two fireflies
// TODO: will ever be the same. We might look at concurrency by then :P
// TODO: Refs:
// TODO:   0: https://github.com/asavie/xdp/blob/master/examples/sendudp/sendudp.go
// TODO:   1: https://lwn.net/Articles/750845/
// TODO:   2: https://www.kernel.org/doc/html/latest/networking/af_xdp.html
func (b *FireflyBackend) sendFirefly(flowID glowdTypes.FlowID) error {
	var err error
	var nlInfo []*glowdTypes.Enrichment

	if b.PollNetlink {
		slog.Debug("beginning netlink polling")
		if flowID.State == glowdTypes.START {
			doneChan, ok := b.ongoingNetlinkConnections.Insert(b.hashFlowID(flowID))
			if !ok {
				go b.pollNetlinkStatus(doneChan, flowID)
			} else {
				slog.Warn("an entry for this flowID already existed", "flowID", flowID)
			}
		} else if flowID.State == glowdTypes.END {
			flowHash := b.hashFlowID(flowID)

			doneChan, ok := b.ongoingNetlinkConnections.Get(flowHash)
			if !ok {
				slog.Warn("found no entry in connection cache for this flowID", "flowID", flowID)
			}

			slog.Debug("dispatching end signal on done channel", "flowID", flowID)
			doneChan <- nil

			slog.Debug("reading back the netlink snapshots")
			nlSnapshot := <-doneChan

			if b.AddNetlinkContext {
				nlInfo = nlSnapshot
			}

			b.ongoingNetlinkConnections.Remove(flowHash)
		}
	}

	var ebpfInfo []*glowdTypes.Enrichment
	if b.PollBPF {
		slog.Debug("beginning ebpf polling")
		auxFlowID := flowID
		// Zero out the addresses to not take them into account when hashing
		auxFlowID.Src.IP = net.IP{}
		auxFlowID.Dst.IP = net.IP{}

		flowHash := b.hashFlowID(auxFlowID)

		if flowID.State == glowdTypes.START {
			slog.Debug("creating ongoing connection", "flowHash", flowHash)
			ok := b.ongoingEbpfConnections.Create(flowHash)
			if ok {
				slog.Warn("an entry for this flowID already existed", "auxFlowID", auxFlowID)
			}
		} else if flowID.State == glowdTypes.END {
			snapshots, ok := b.ongoingEbpfConnections.Get(flowHash)
			if !ok {
				slog.Warn("found no entry in ebpf connection cache for this flowID", "auxFlowID", auxFlowID)
			}

			if b.AddBPFContext {
				ebpfInfo = snapshots
			}

			b.ongoingEbpfConnections.Remove(flowHash)
		}
	}

	var localFirefly glowdTypes.Firefly
	localFirefly.Version = glowdTypes.FIREFLY_VERSION

	localFirefly.FlowLifecycle.State = flowID.State.String()
	localFirefly.FlowLifecycle.CurrentTime = time.Now().UTC().Format(glowdTypes.TIME_FORMAT)

	localFirefly.FlowID.AFI = flowID.Family.String()
	localFirefly.FlowID.SrcIP = flowID.Src.IP.String()
	localFirefly.FlowID.DstIP = flowID.Dst.IP.String()
	localFirefly.FlowID.Protocol = flowID.Protocol.String()
	localFirefly.FlowID.SrcPort = flowID.Src.Port
	localFirefly.FlowID.DstPort = flowID.Dst.Port

	localFirefly.Context.ExperimentID = flowID.Experiment
	localFirefly.Context.ActivityID = flowID.Activity
	localFirefly.Context.Application = glowdTypes.APPLICATION

	localFirefly.Netlink = nlInfo
	localFirefly.EbpfTcpInfo = ebpfInfo

	localFirefly.ParseTimeStamps(flowID)

	// TODO: If src IP address is private, get one through STUN!

	payload, err := json.Marshal(localFirefly)
	if err != nil {
		return fmt.Errorf("error marshalling firefly: %w", err)
	}

	if b.PrependSyslog {
		syslogHeader := []byte(fmt.Sprintf(glowdTypes.SYSLOG_HEADER, localFirefly.FlowLifecycle.CurrentTime))
		payload = append(syslogHeader, payload...)
	}

	sendErrors := []error{}
	if err := b.sendToDestination(flowID.Family, flowID.Dst.IP, payload); err != nil {
		sendErrors = append(sendErrors, err)
		slog.Error("couldn't send the firefly to the destination", "err", err)
	}

	if b.SendToCollector {
		if err := b.sendToCollector(payload); err != nil {
			sendErrors = append(sendErrors, err)
		}
	}

	// errors.Join will return nil if all the errors are nil!
	return errors.Join(sendErrors...)
}

func (b *FireflyBackend) sendToCollector(payload []byte) error {
	slog.Debug("sending firefly to the collector")

	if _, err := b.collectorConn.Write(payload); err != nil {
		// Be sure to check udp(7)
		if errors.Is(err, syscall.ECONNREFUSED) {
			slog.Warn("got ECONNREFUSED when sending, retrying once...")
			if _, err := b.collectorConn.Write(payload); err != nil {
				return fmt.Errorf("error sending the firefly to the collector: %w", err)
			}
		} else {
			return fmt.Errorf("error sending the firefly to the collector: %w", err)
		}
	}

	return nil
}

func (b *FireflyBackend) sendToDestination(family glowdTypes.Family, destIP net.IP, payload []byte) error {
	addressFmt := "[%s]:%d"
	if family == glowdTypes.IPv4 {
		addressFmt = "%s:%d"
	}
	conn, err := net.Dial("udp", fmt.Sprintf(addressFmt, destIP, b.FireflyDestinationPort))
	if err != nil {
		return fmt.Errorf("couldn't initialize UDP socket: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Warn("error closing UDP socket", "err", err)
		}
	}()

	slog.Debug("sending firefly", "dst", destIP, "size", len(payload))
	if _, err = conn.Write(payload); err != nil {
		return fmt.Errorf("couldn't send the firefly to the destination: %w", err)
	}

	return nil
}
