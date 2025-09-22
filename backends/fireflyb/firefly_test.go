package fireflyb

import (
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/scitags/flowd-go/types"
)

func TestParseCollectorAddress(t *testing.T) {
	port := 1234

	tests := []struct {
		in   string
		want string
	}{
		{"0.0.0.0", fmt.Sprintf("0.0.0.0:%d", port)},
		{"127.0.0.1", fmt.Sprintf("127.0.0.1:%d", port)},
		{"example.net", fmt.Sprintf("example.net:%d", port)},
		{"example.org", fmt.Sprintf("example.org:%d", port)},
		{"::1", fmt.Sprintf("[::1]:%d", port)},
		{"fe80::3333:2222:1111:0000", fmt.Sprintf("[fe80::3333:2222:1111:0000]:%d", port)},
	}

	for _, test := range tests {
		if got := parseCollectorAddress(test.in, port); got != test.want {
			t.Errorf("got %s != %s", got, test.want)
		}
	}
}

// Define flags we can pass to 'go test'; the harness already parses them!
var (
	dstIp   = flag.String("dst-ip", "127.0.0.1", "iperf3 server address")
	srcPort = flag.String("src-port", "2345", "iperf3 client source port")
	dstPort = flag.String("dst-port", "5777", "iperf3 server port")

	// Check 'sysctl net.ipv4.tcp_available_congestion_control' for other options.
	// You can also load other algorithms not loaded by default with modprobe(8);
	// available modules are under '/lib/modules/`uname -r`/kernel/net/ipv4/tcp*'.
	congAlg    = flag.String("cong-alg", "cubic", "iperf3 congestion algorithm")
	runtimeSec = flag.Uint("runtime-sec", 300, "iperf3 runtime in seconds")
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

// iperf3 -c 2001:720:420:c002::a --cport 2345 --time 300 -p 5777 -i 1 -J
func runIperf3(wg *sync.WaitGroup, dstIP string, srcPort string, dstPort string, runtime uint, cAlg string) {
	defer wg.Done()

	cmd := exec.Command("iperf3",
		"--client", dstIP,
		"--cport", srcPort,
		"--port", dstPort,
		"--time", fmt.Sprintf("%d", runtime),
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

func TestEnv(t *testing.T) {
	slog.Debug("env vars", "dstIp", *dstIp, "srcPort", *srcPort, "dstPort", *dstPort, "runtimeSec", *runtimeSec, "congAlg", *congAlg)
}

// Please note the derivation of additional TCP information parameters is based on iperf3's implementation
// as seen on https://github.com/esnet/iperf/blob/204421d895ef7b7a6546c3b8f42aae24ffa99950/src/tcp_info.c
func TestPeriodicFirefly(t *testing.T) {
	// Start the server listening for fireflies
	conn, err := net.ListenPacket("udp", "localhost:4321")
	if err != nil {
		t.Logf("error creating the UDP server: %v\n", err)
		t.FailNow()
	}
	defer conn.Close()

	fireflyBackend := FireflyBackend{
		PrependSyslog: false,

		SendToCollector:  true,
		CollectorAddress: "127.0.0.1",
		CollectorPort:    4321,

		PeriodicFireflies:   true,
		Period:              100,
		EnrichmentVerbosity: "lean",

		AddNetlinkContext: true,

		AddBPFContext: true,
		Strategy:      "poll",
		DebugMode:     true,
	}

	if err := fireflyBackend.Init(); err != nil {
		t.Logf("couldn't initialise the firefly plugin: %v\n", err)
		t.FailNow()
	}
	defer func() {
		if err := fireflyBackend.Cleanup(); err != nil {
			t.Logf("error cleaning up the firefly plugin: %v\n", err)
		}
	}()

	flowdIdChan := make(chan types.FlowID)
	doneChan := make(chan struct{})

	go fireflyBackend.Run(doneChan, flowdIdChan)

	dummyFlow := types.FlowID{
		State:       types.START,
		Family:      types.IPv6,
		Src:         types.IPPort{IP: net.ParseIP("::"), Port: 2345},
		Dst:         types.IPPort{IP: net.ParseIP("::"), Port: 5777},
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
		time.Sleep(time.Duration(*runtimeSec+10) * time.Second)
		dummyFlow.State = types.END
		flowdIdChan <- dummyFlow

		slog.Debug("closing the done channel in 20 seconds")
		time.Sleep(20 * time.Second)
		close(doneChan)
	}()

	time.Sleep(1 * time.Second)

	wg.Add(1)
	go runIperf3(&wg, *dstIp, *srcPort, *dstPort, *runtimeSec, *congAlg)

	slog.Debug("waiting for everything to finish...")
	wg.Wait()
}
