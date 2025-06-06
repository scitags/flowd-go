//go:build linux && cgo

package skops_test

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/scitags/flowd-go/backends/fireflyb"
	"github.com/scitags/flowd-go/enrichment/skops"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time.
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			// Remove the directory from the source's filename.
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)
			}
			return a
		},
	}))
	slog.SetDefault(logger)
}

func TestEbpfAttach(t *testing.T) {
	if err := skops.Init(); err != nil {
		t.Errorf("error attaching the program: %v\n", err)
	}
}

// Please note the derivation of additional TCP information parameters is based on iperf3's implementation
// as seen on https://github.com/esnet/iperf/blob/204421d895ef7b7a6546c3b8f42aae24ffa99950/src/tcp_info.c
func TestGatherFirefly(t *testing.T) {
	fireflyBackend := fireflyb.FireflyBackend{
		PrependSyslog: false,

		SendToCollector:  true,
		CollectorAddress: "127.0.0.1",
		CollectorPort:    4321,

		AddNetlinkContext: true,
		AddBPFContext:     true,

		PollBPF:                true,
		PollNetlink:            true,
		NetlinkPollingInterval: 1000,
	}

	if err := fireflyBackend.Init(); err != nil {
		t.Logf("couldn't initialise the firefly plugin: %v\n", err)
		t.Fail()
	}
	defer func() {
		if err := fireflyBackend.Cleanup(); err != nil {
			t.Logf("error cleaning up the firefly plugin: %v\n", err)
		}
	}()

	flowdIdChan := make(chan glowdTypes.FlowID)
	doneChan := make(chan struct{})

	go fireflyBackend.Run(doneChan, flowdIdChan)

	dummyFlow := glowdTypes.FlowID{
		State:      glowdTypes.START,
		Family:     glowdTypes.IPv6,
		Src:        glowdTypes.IPPort{IP: net.ParseIP("::"), Port: 2345},
		Dst:        glowdTypes.IPPort{IP: net.ParseIP("::"), Port: 5777},
		Experiment: 0,
		Activity:   0,
	}

	// Simply track a specific flow. We're creating them with:
	//   iperf3 -c target.iperf3.server --cport 2345 -p 5777
	flowdIdChan <- dummyFlow

	conn, err := net.ListenPacket("udp", "localhost:4321")
	if err != nil {
		t.Logf("error creating the UDP server: %v\n", err)
		t.FailNow()
	}
	defer conn.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buff := make([]byte, 1024*1000)
		fd, err := os.Create("fireflies.json")
		if err != nil {
			slog.Warn("couldn't open the output file", "err", err)
			return
		}
		defer fd.Close()

		// gotFirstFirefly := false
		for {
			select {
			case <-doneChan:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, addr, err := conn.ReadFrom(buff)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					slog.Debug("timeout on reception")
					continue
				}
				if err != nil {
					slog.Warn("error reading back data", "err", err)
					continue
				}
				slog.Debug("read data", "n", n, "addr", addr, "msg", buff[:n])

				// if !gotFirstFirefly {
				// 	slog.Debug("got the first firefly...")
				// 	gotFirstFirefly = true
				// 	continue
				// }

				slog.Debug("writing the data...")
				if _, err := fd.Write(buff[:n]); err != nil {
					slog.Warn("error writing to the output file", "err", err)
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		time.Sleep(190 * time.Second)
		dummyFlow.State = glowdTypes.END
		flowdIdChan <- dummyFlow
		wg.Done()
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	for sig := range sigChan {
		t.Logf("received signal %s, quitting\n", sig)
		close(doneChan)
		wg.Wait()
		return
	}
}
