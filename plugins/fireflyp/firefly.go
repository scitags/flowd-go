package fireflyp

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	glowdTypes "github.com/scitags/flowd-go/types"
)

type FireflyPlugin struct {
	Config

	listener   *net.UDPConn
	forwarders []*net.UDPConn
}

func (p *FireflyPlugin) String() string {
	return "firefly"
}

func NewFireflyPlugin(c *Config) (*FireflyPlugin, error) {
	p := FireflyPlugin{Config: *c}

	slog.Debug("initialising the firefly plugin")
	if p.BufferSize < minRecvBufferSize {
		return nil, fmt.Errorf("UDP receive buffer size (%d) is too small, make it at least 2048 bytes", p.BufferSize)
	}

	bindAddr := net.ParseIP(p.BindAddress)
	if bindAddr == nil {
		return nil, fmt.Errorf("invalid IP address %q specified", p.BindAddress)
	}

	listener, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   bindAddr,
		Port: int(p.BindPort),
	})
	if err != nil {
		return nil, fmt.Errorf("error setting up the UDP listener: %w", err)
	}

	p.listener = listener

	// Set up outbound UDP connections for each firefly receiver.
	for _, receiver := range p.FireflyReceivers {
		dstAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", receiver.Address, receiver.Port))
		if err != nil {
			return nil, fmt.Errorf("error resolving firefly receiver %q:%d: %w", receiver.Address, receiver.Port, err)
		}
		conn, err := net.DialUDP("udp", nil, dstAddr)
		if err != nil {
			return nil, fmt.Errorf("error creating UDP forwarder to firefly receiver %q:%d: %w", receiver.Address, receiver.Port, err)
		}
		slog.Debug("firefly plugin: will forward to firefly receiver", "address", receiver.Address, "port", receiver.Port)
		p.forwarders = append(p.forwarders, conn)
	}

	return &p, nil
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

			msg := recvBuffer[:n]

			// Forward the raw datagram to all configured firefly receivers.
			for _, fwd := range p.forwarders {
				go func(conn *net.UDPConn, data []byte) {
					if _, err := conn.Write(data); err != nil {
						slog.Error("error forwarding firefly datagram to receiver",
							"dst", conn.RemoteAddr(), "err", err)
					} else {
						slog.Debug("forwarded firefly datagram to receiver", "dst", conn.RemoteAddr())
					}
				}(fwd, msg)
			}

			go func(msg []byte) {
				slog.Debug("serving an incoming UDP firefly")

				auxFirefly := glowdTypes.SlimFirefly{}
				if err := auxFirefly.Parse(msg); err != nil {
					slog.Error("couldn't parse the incoming firefly", "err", err,
						"hasSyslogHeader", p.HasSyslogHeader)
				}

				outChan <- auxFirefly.FlowID

			}(msg)
		}
	}
}

func (p *FireflyPlugin) Cleanup() error {
	slog.Debug("cleaning up the firefly plugin")

	// Close all firefly receiver connections.
	for _, fwd := range p.forwarders {
		if err := fwd.Close(); err != nil {
			slog.Error("error closing firefly receiver connection", "dst", fwd.RemoteAddr(), "err", err)
		}
	}

	if err := p.listener.Close(); err != nil {
		slog.Error("error closing the UDP listener", "err", err)
	}
	return nil
}
