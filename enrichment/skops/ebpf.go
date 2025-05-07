//go:build linux && cgo

package skops

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unsafe"

	libbpf "github.com/aquasecurity/libbpfgo"
)

const PROG_NAME string = "connTracker"
const RINGBUFF_NAME string = "tcpStats"
const MAP_NAME string = "flowsToFollow"
const POLL_INTERVAL_MS int = 300

var (
	//go:embed progs/sk_ops.bpf.o
	skOpsBPFProg []byte

	logLevelTranslation = map[slog.Level]int{
		slog.LevelDebug: libbpf.LibbpfDebugLevel,
		slog.LevelInfo:  libbpf.LibbpfInfoLevel,
		slog.LevelWarn:  libbpf.LibbpfWarnLevel,
	}
)

type FlowSpec struct {
	DstPort uint32
	SrcPort uint32
}

type EbpfEnricher struct {
	module    *libbpf.Module
	link      *libbpf.BPFLink
	FlowMap   *libbpf.BPFMap
	ringBuff  *libbpf.RingBuffer
	eventChan chan []byte
}

func (e *EbpfEnricher) Cleanup() {
	e.ringBuff.Close()
	e.link.Destroy()
	e.module.Close()
}

func NewEnricher() (*EbpfEnricher, error) {
	slog.Debug("initialising the eBPF backend")

	e := EbpfEnricher{}

	cgroupPath, err := GetCgroupInfo()
	if err != nil {
		return nil, fmt.Errorf("couldn't get cgroup information: %w", err)
	}

	// Setup the logging from libbpf
	setupLogging()

	// Create the BPF module
	bpfModule, err := libbpf.NewModuleFromBuffer(skOpsBPFProg, "sk_ops")
	if err != nil {
		return nil, fmt.Errorf("error creating the BPF module: %w", err)
	}
	e.module = bpfModule

	// Try to load the module's object
	if err := e.module.BPFLoadObject(); err != nil {
		return nil, fmt.Errorf("error loading the BPF object: %w", err)
	}

	prog, err := e.module.GetProgram(PROG_NAME)
	if prog == nil || err != nil {
		return nil, fmt.Errorf("couldn't find the target program %s: %w", PROG_NAME, err)
	}

	link, err := prog.AttachCgroup(fmt.Sprintf("/sys/fs/cgroup/%s", cgroupPath))
	if err != nil {
		return nil, fmt.Errorf("couldn't attach the program to the given cgroup: %w", err)
	}
	e.link = link

	bpfMap, err := bpfModule.GetMap(MAP_NAME)
	if err != nil {
		return nil, fmt.Errorf("error getting the ebpf map: %w", err)
	}
	e.FlowMap = bpfMap

	e.eventChan = make(chan []byte)
	rb, err := e.module.InitRingBuf(RINGBUFF_NAME, e.eventChan)
	if err != nil {
		return nil, fmt.Errorf("error initializing the ring buffer: %w", err)
	}
	e.ringBuff = rb

	return &e, nil
}

func (e *EbpfEnricher) Run(done <-chan struct{}, outChan chan<- TcpInfo) {
	slog.Debug("begin reading the ring buffer")

	tcpInfo := TcpInfo{}
	e.ringBuff.Poll(POLL_INTERVAL_MS)

	for {
		select {
		case <-done:
			slog.Debug("cleanly exiting the ebpf enricher")
			close(e.eventChan)
			return
		case event, ok := <-e.eventChan:
			if !ok {
				slog.Warn("somebody closed the ring buffer's channel!")
				return
			}
			// slog.Debug("event", "raw", event)
			if err := tcpInfo.UnmarshalBinary(event); err != nil {
				slog.Warn("error unmarshaling event", "err", err)
			}

			outChan <- tcpInfo

			// slog.Debug("tcpInfo", "state", tcpInfo.State, "caAlg", tcpInfo.CaAlg, "caState", tcpInfo.CaState)
		}
	}
}

func setupLogging() {
	slog.Debug("setting up logging")
	libbpfLogLevel := libbpf.LibbpfWarnLevel
	if slog.Default().Handler().Enabled(context.TODO(), slog.LevelDebug) {
		libbpfLogLevel = logLevelTranslation[slog.LevelDebug]
	} else if slog.Default().Handler().Enabled(context.TODO(), slog.LevelInfo) {
		libbpfLogLevel = logLevelTranslation[slog.LevelInfo]
	}

	libbpf.SetLoggerCbs(libbpf.Callbacks{
		Log: func(level int, msg string) {
			if level <= libbpfLogLevel {
				// Remove the trailing newline coming from C-land...
				for _, line := range strings.Split(msg, "\n") {
					if line != "" {
						slog.Info(line)
					}
				}

			}
		},
	})
}

func Init() error {
	slog.Debug("initialising the eBPF backend")

	cgroupPath, err := GetCgroupInfo()
	if err != nil {
		return fmt.Errorf("couldn't get cgroup information: %w", err)
	}

	// Setup the logging from libbpf
	setupLogging()

	// Create the BPF module
	bpfModule, err := libbpf.NewModuleFromBuffer(skOpsBPFProg, "sk_ops")
	if err != nil {
		return fmt.Errorf("error creating the BPF module: %w", err)
	}
	defer bpfModule.Close()

	// Try to load the module's object
	if err := bpfModule.BPFLoadObject(); err != nil {
		return fmt.Errorf("error loading the BPF object: %w", err)
	}

	prog, err := bpfModule.GetProgram(PROG_NAME)
	if prog == nil || err != nil {
		return fmt.Errorf("couldn't find the target program %s: %w", PROG_NAME, err)
	}

	link, err := prog.AttachCgroup(fmt.Sprintf("/sys/fs/cgroup/%s", cgroupPath))
	if err != nil {
		return fmt.Errorf("couldn't attach the program to the given cgroup: %w", err)
	}
	defer link.Destroy()

	bpfMap, err := bpfModule.GetMap("flowsToFollow")
	if err != nil {
		return fmt.Errorf("error getting the ebpf map: %w", err)
	}

	fSpec := FlowSpec{
		DstPort: 5201,
		SrcPort: 2345,
	}
	var dummy byte = 1

	flowSpecPtr := unsafe.Pointer(&fSpec)
	dummyPtr := unsafe.Pointer(&dummy)
	if err := bpfMap.Update(flowSpecPtr, dummyPtr); err != nil {
		return fmt.Errorf("error inserting map value: %w", err)
	}

	eventChan := make(chan []byte)
	rb, err := bpfModule.InitRingBuf(RINGBUFF_NAME, eventChan)
	if err != nil {
		return fmt.Errorf("error initializing the ring buffer: %w", err)
	}
	defer rb.Close()

	rb.Poll(POLL_INTERVAL_MS)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		slog.Debug("waiting to receive SIGTERM")
		<-sigChan
		slog.Debug("received SIGTERM: stopping polling")
		rb.Stop()
	}()

	slog.Debug("begin reading the ring buffer")
	tcpInfo := TcpInfo{}
	for event := range eventChan {
		// slog.Debug("event", "raw", event)
		if err := tcpInfo.UnmarshalBinary(event); err != nil {
			slog.Warn("error unmarshaling event", "err", err)
			continue
		}
		// for i := 0; i < len(event); i++ {
		// 	fmt.Printf("event[%d] = %d\n", i, event[i])
		// }
		// fmt.Printf("tcpInfo: %s\n", tcpInfo)
		slog.Debug("tcpInfo", "src", tcpInfo.SrcPort, "dst", tcpInfo.DstPort, "sentMBytes", tcpInfo.BytesSent/(1024*1024), "cwnd", tcpInfo.SndCwnd, "mss", tcpInfo.SndMss, "state", tcpInfo.State, "caAlg", tcpInfo.CaAlg, "caState", tcpInfo.CaState)
	}
	slog.Debug("bye!")

	return nil
}
