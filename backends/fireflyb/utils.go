package fireflyb

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"
	"time"

	"github.com/scitags/flowd-go/netlink"
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
	var nlInfo *netlink.InetDiagTCPInfoResp
	if b.AddNetlinkContext {
		nlInfo, err = b.addNetlinkContext(uint8(flowID.Family), flowID.Src.Port, flowID.Dst.Port)
		if err != nil {
			slog.Warn("error getting info from netlink, proceeding without it", "err", err)

			// Even though this should already be the case, be explicit!
			nlInfo = nil
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

	slog.Debug("sending firefly", "dst", destIP)
	if _, err = conn.Write(payload); err != nil {
		return fmt.Errorf("couldn't send the firefly to the destination: %w", err)
	}

	return nil
}

func (b *FireflyBackend) addNetlinkContext(family uint8, srcPort, dstPort uint16) (*netlink.InetDiagTCPInfoResp, error) {
	nlReplies, err := netlink.NewTCPDiagRequest(family, srcPort, dstPort).ExecuteRequest()
	if err != nil {
		return nil, fmt.Errorf("couldn't execute the netlink request: %w", err)
	}

	switch len(nlReplies) {
	case 0:
		return nil, fmt.Errorf("got no information from netlink")
	case 1:
		return nlReplies[0], nil
	default:
		slog.Warn("got information for more than one flow...")

		// TODO: Filter replies from netlink based on IPv{4,6} addresses
		return nlReplies[0], nil
	}
}
