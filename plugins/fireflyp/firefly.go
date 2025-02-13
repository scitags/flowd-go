package fireflyp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	glowdTypes "github.com/scitags/flowd-go/types"
)

const (
	minRecvBufferSize uint32 = 2048
)

var (
	Defaults = map[string]interface{}{
		"bindAddress":     "127.0.0.1",
		"bindPort":        10514,
		"bufferSize":      2 * minRecvBufferSize,
		"deadline":        0,
		"hasSyslogHeader": true,
	}
)

type FireflyPlugin struct {
	BindAddress     string `json:"bindAddress"`
	BindPort        uint16 `json:"bindPort"`
	BufferSize      uint32 `json:"bufferSize"`
	Deadline        uint32 `json:"deadline"`
	HasSyslogHeader bool   `json:"hasSyslogHeader"`

	listener *net.UDPConn
}

func (p *FireflyPlugin) String() string {
	return "firefly"
}

// Just implement the glowd.Backend interface
func (p *FireflyPlugin) Init() error {
	slog.Debug("initialising the firefly plugin")
	if p.BufferSize < minRecvBufferSize {
		return fmt.Errorf("UDP receive buffer size (%d) is too small, make it at least 2048 bytes", p.BufferSize)
	}

	bindAddr := net.ParseIP(p.BindAddress)
	if bindAddr == nil {
		return fmt.Errorf("invalid IP address %q specified", p.BindAddress)
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   bindAddr,
		Port: int(p.BindPort),
	})
	if err != nil {
		return fmt.Errorf("error setting up the UDP listener: %w", err)
	}

	p.listener = listener

	return nil
}

func (p *FireflyPlugin) Run(done <-chan struct{}, outChan chan<- glowdTypes.FlowID) {
	slog.Debug("running the firefly plugin")

	for {
		select {
		case <-done:
			slog.Debug("cleanly exiting the firefly plugin")
			return
		default:
			recvBuffer := make([]byte, p.BufferSize)

			if p.Deadline > 0 {
				p.listener.SetDeadline(time.Now().Add(time.Duration(p.Deadline) * time.Second))
			}

			// Look into leveraging SO_REUSEPORT!
			n, addr, err := p.listener.ReadFromUDP(recvBuffer)
			if err != nil {
				if errors.Is(err, os.ErrDeadlineExceeded) {
					slog.Debug("deadline exceeded...")
					continue
				}
				slog.Error("error reading from UDP", "err", err)
				continue
			}
			slog.Debug("read from UDP", "n", n, "from", *addr)

			go func(msg []byte) {
				slog.Debug("serving an incoming UDP firefly")

				auxFirefly, err := parseFirefly(msg, p.HasSyslogHeader)
				if err != nil {
					slog.Error("couldn't parse the incoming firefly", "err", err,
						"hasSyslogHeader", p.HasSyslogHeader)
				}

				outChan <- auxFirefly.FlowID

			}(recvBuffer[:n])
		}
	}
}

func (p *FireflyPlugin) Cleanup() error {
	slog.Debug("cleaning up the firefly plugin")
	if err := p.listener.Close(); err != nil {
		slog.Error("error closing the UDP listener", "err", err)
	}
	return nil
}

func parseFirefly(msg []byte, hasSyslogHeader bool) (glowdTypes.AuxFirefly, error) {
	auxFirefly := glowdTypes.AuxFirefly{}
	jsonIndex := 0

	if hasSyslogHeader {
		jsonIndex = strings.Index(string(msg), "{")
		if jsonIndex == -1 {
			return auxFirefly, fmt.Errorf("couldn't find the beginning of the JSON")
		}
	}

	if err := json.Unmarshal(msg[jsonIndex:], &auxFirefly); err != nil {
		return auxFirefly, fmt.Errorf("couldn't unmarhsal incoming firefly: %w", err)
	}

	return auxFirefly, nil
}
