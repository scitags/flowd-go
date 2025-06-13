package fireflyb

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"syscall"

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
func (b *FireflyBackend) sendFirefly(flowID glowdTypes.FlowID, payload []byte) error {
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
