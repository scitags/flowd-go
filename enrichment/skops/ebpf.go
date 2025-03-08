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

	libbpf "github.com/aquasecurity/libbpfgo"
)

const PROG_NAME string = "connTracker"
const RINGBUFF_NAME string = "tcpStats"
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

type FlowFourTuple struct {
	IPv6Hi  uint64
	IPv6Lo  uint64
	DstPort uint16
	SrcPort uint16
}

func SetupLogging() {
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
	SetupLogging()

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
		}
		// for i := 0; i < len(event); i++ {
		// 	fmt.Printf("event[%d] = %d\n", i, event[i])
		// }
		// fmt.Printf("tcpInfo: %s\n", tcpInfo)
		slog.Debug("tcpInfo", "state", tcpInfo.State, "caAlg", tcpInfo.CaAlg, "caState", tcpInfo.CaState)
	}
	slog.Debug("bye!")

	return nil
}
