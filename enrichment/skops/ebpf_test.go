//go:build linux

package skops_test

import (
	"errors"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/scitags/flowd-go/backends/fireflyb"
	glowdTypes "github.com/scitags/flowd-go/types"
)

var (
	SRC_PORT    string
	DST_PORT    string
	RUNTIME_SEC string
	CONG_ALG    string
	DST_IP      string
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

	// Populate the configuration variables
	var ok bool

	DST_IP, ok = os.LookupEnv("DST_IP")
	if !ok {
		DST_IP = "127.0.0.1"
	}

	SRC_PORT, ok = os.LookupEnv("SRC_PORT")
	if !ok {
		SRC_PORT = "2345"
	}

	DST_PORT, ok = os.LookupEnv("DST_PORT")
	if !ok {
		DST_PORT = "5777"
	}

	RUNTIME_SEC, ok = os.LookupEnv("RUNTIME_SEC")
	if !ok {
		RUNTIME_SEC = "300"
	}

	// Check 'sysctl net.ipv4.tcp_available_congestion_control' for other options.
	// You can also load other algorithms not loaded by default with modprobe(8);
	// available modules are under '/lib/modules/`uname -r`/kernel/net/ipv4/tcp*'.
	CONG_ALG, ok = os.LookupEnv("CONG_ALG")
	if !ok {
		CONG_ALG = "cubic"
	}
}

// iperf3 -c 2001:720:420:c002::a --cport 2345 --time 300 -p 5777 -i 1 -J
func runIperf3(wg *sync.WaitGroup, dstIP string, srcPort string, dstPort string, runtime string, cAlg string) {
	defer wg.Done()

	cmd := exec.Command("iperf3",
		"--client", dstIP,
		"--cport", srcPort,
		"--port", dstPort,
		"--time", runtime,
		"--congestion", cAlg,
		"--interval", "1",
		"--json",
	)

	slog.Debug("running iperf3", "args", cmd.Args)

	fd, err := os.Create("iperf3.json")
	if err != nil {
		slog.Warn("couldn't open the output file", "err", err)
		return
	}
	defer fd.Close()

	cmd.Stdout = fd
	cmd.Stderr = fd

	if err := cmd.Run(); err != nil {
		slog.Error("error running iperf3", "err", err)
	}
}

// Please note the derivation of additional TCP information parameters is based on iperf3's implementation
// as seen on https://github.com/esnet/iperf/blob/204421d895ef7b7a6546c3b8f42aae24ffa99950/src/tcp_info.c
func TestGatherFirefly(t *testing.T) {
	runtimeParsed, err := strconv.ParseInt(RUNTIME_SEC, 10, 64)
	if err != nil {
		t.Errorf("couldn't parse provided runtime: %v\n", err)
		t.FailNow()
	}

	// Start the server listening for fireflies
	conn, err := net.ListenPacket("udp", "localhost:4321")
	if err != nil {
		t.Logf("error creating the UDP server: %v\n", err)
		t.FailNow()
	}
	defer conn.Close()

	fireflyBackend := fireflyb.FireflyBackend{
		PrependSyslog: false,

		SendToCollector:  true,
		CollectorAddress: "127.0.0.1",
		CollectorPort:    4321,

		AddNetlinkContext: true,
		AddBPFContext:     true,

		PeriodicFireflies: true,
		Period:            500,

		EnrichmentVerbosity: "lean",
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
		State:       glowdTypes.START,
		Family:      glowdTypes.IPv6,
		Src:         glowdTypes.IPPort{IP: net.ParseIP("::"), Port: 2345},
		Dst:         glowdTypes.IPPort{IP: net.ParseIP("::"), Port: 5777},
		Experiment:  0,
		Activity:    0,
		Application: "ipef3Tests",
	}

	// Simply track a specific flow. We're creating them with:
	//   iperf3 -c target.iperf3.server --cport 2345 -p 5777
	flowdIdChan <- dummyFlow

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buff := make([]byte, 1024*1000)
		fd, err := os.Create("fireflies.jsonl")
		if err != nil {
			slog.Warn("couldn't open the output file", "err", err)
			return
		}
		defer fd.Close()

		for {
			select {
			case <-doneChan:
				return
			default:
				conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				n, _, err := conn.ReadFrom(buff)
				if errors.Is(err, os.ErrDeadlineExceeded) {
					slog.Debug("timeout on reception")
					continue
				}
				if err != nil {
					slog.Warn("error reading back data", "err", err)
					continue
				}

				slog.Debug("writing the data...")
				if _, err := fd.Write(append(buff[:n], '\n')); err != nil {
					slog.Warn("error writing to the output file", "err", err)
				}
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(time.Duration(runtimeParsed+10) * time.Second)
		dummyFlow.State = glowdTypes.END
		flowdIdChan <- dummyFlow

		slog.Debug("closing the done channel in 20 seconds")
		time.Sleep(20 * time.Second)
		close(doneChan)
	}()

	time.Sleep(1 * time.Second)

	wg.Add(1)
	go runIperf3(&wg, DST_IP, SRC_PORT, DST_PORT, RUNTIME_SEC, CONG_ALG)

	slog.Debug("waiting for everything to finish...")
	wg.Wait()
}
