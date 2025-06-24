package fireflyb

import (
	"fmt"
	"hash/maphash"
	"log/slog"
	"net"
	"strings"

	glowdTypes "github.com/scitags/flowd-go/types"
)

var (
	Defaults = map[string]interface{}{
		"fireflyDestinationPort": 10514,
		"prependSyslog":          true,
		"addNetlinkContext":      true,
		"sendToCollector":        false,
		"collectorAddress":       "127.0.0.1",
		"collectorPort":          10514,
		"pollNetlink":            false,
		"netlinkPollingInterval": 5000,
	}
)

type FireflyBackend struct {
	FireflyDestinationPort uint16 `json:"fireflyDestinationPort"`
	PrependSyslog          bool   `json:"prependSyslog"`
	AddNetlinkContext      bool   `json:"addNetlinkContext"`
	SendToCollector        bool   `json:"sendToCollector"`
	CollectorAddress       string `json:"collectorAddress"`
	CollectorPort          int    `json:"collectorPort"`
	PollNetlink            bool   `json:"pollNetlink"`
	NetlinkPollingInterval int    `json:"netlinkPollingInterval"`

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

	if b.SendToCollector {
		addressFmt := "%s:%d"
		// If we got an IPv6 address...
		if pIP := net.ParseIP(b.CollectorAddress); pIP != nil && strings.Contains(b.CollectorAddress, ":") {
			addressFmt = "[%s]:%d"
		}

		conn, err := net.Dial("udp", fmt.Sprintf(addressFmt, b.CollectorAddress, b.CollectorPort))
		if err != nil {
			return fmt.Errorf("couldn't initialize UDP socket: %w", err)
		}

		b.collectorConn = conn
	}

	slog.Debug("initialising the ongoing connections map")
	b.ongoingConnections = NewConnectionCache(100)

	slog.Debug("initialising the hash generator")
	b.hashGen = maphash.Hash{}

	return nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan glowdTypes.FlowID) {
	slog.Debug("running the firefly backend")
	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID")
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

	return nil
}
