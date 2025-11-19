package xrootd

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/jellydator/ttlcache/v3"
)

type XrootdProcessor struct {
	Config

	listener *net.UDPConn

	// serverId -> (stream code, expected sequence number)
	sequenceCache *ttlcache.Cache[string, map[byte]byte]

	transferCache *ttlcache.Cache[string, TransferCacheValue]
}

func (p *XrootdProcessor) String() string {
	return "xrootd"
}

func NewXrootdProcessor(c *Config) (*XrootdProcessor, error) {
	p := XrootdProcessor{Config: *c}

	slog.Debug("initialising the xrootd processor")
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

	// Initialise caches
	p.sequenceCache = ttlcache.New(ttlcache.WithTTL[string, map[byte]byte](time.Duration(c.CacheTTL) * time.Second))
	p.transferCache = ttlcache.New(ttlcache.WithTTL[string, TransferCacheValue](time.Duration(c.CacheTTL) * time.Second))

	return &p, nil
}

func (p *XrootdProcessor) Run(done <-chan struct{}) {
	slog.Debug("running the xrootd processor")

	recvBuffer := make([]byte, p.BufferSize)
	for {
		select {
		case <-done:
			slog.Debug("cleanly exiting the xrootd processor")
			return
		default:
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

			go func(raw []byte) {
				msg, err := ParseDatagram(raw)
				if err != nil {
					slog.Error("error unmarshaling", "err", err)
				}

				// slog.Debug("decoded:", "msg", msg)
				fmt.Printf("decoded:\n\n%+v\n\n", msg)

				p.Process(msg, addr)

			}(recvBuffer[:n])
		}
	}
}

func (p *XrootdProcessor) Cleanup() error {
	slog.Debug("cleaning up the xrootd processor")
	if err := p.listener.Close(); err != nil {
		slog.Error("error closing the UDP listener", "err", err)
	}
	return nil
}
