//go:build linux

package skops

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

//go:embed progs/sk_ops.bpf.o
var skOpsBPFProg []byte

type FlowSpec struct {
	DstPort uint32
	SrcPort uint32
}

type EbpfEnricher struct {
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader

	wg *sync.WaitGroup
}

func (e *EbpfEnricher) Cleanup() {
	// Note the ringbuff reader is closed by CloseBuffer
	e.link.Close()
	e.coll.Close()
}

func NewEnricher(pollingInterval uint64) (*EbpfEnricher, error) {
	slog.Debug("initialising the eBPF backend")

	e := EbpfEnricher{}

	cgroupPath, err := GetCgroupInfo()
	if err != nil {
		return nil, fmt.Errorf("couldn't get cgroup information: %w", err)
	}

	coll, err := loadProg(skOpsBPFProg, pollingInterval)
	if err != nil {
		return nil, fmt.Errorf("error loading the eBPF program: %w", err)
	}
	e.coll = coll

	rd, err := ringbuf.NewReader(coll.Maps[RINGBUFF_NAME])
	if err != nil {
		e.coll.Close()
		return nil, fmt.Errorf("error setting up the ringbuffer reader: %w", err)
	}
	e.reader = rd

	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    fmt.Sprintf("/sys/fs/cgroup/%s", cgroupPath),
		Program: e.coll.Programs[PROG_NAME],
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		e.coll.Close()
		return nil, fmt.Errorf("couldn't attach the program to the given cgroup: %w", err)
	}
	e.link = link

	// Sync the reader goroutine
	e.wg = &sync.WaitGroup{}

	return &e, nil
}

// Pulled from cilium examples, should we do something fancy like this?
func findCgroupPath() (string, error) {
	cgroupPath := "/sys/fs/cgroup"

	var st syscall.Statfs_t
	err := syscall.Statfs(cgroupPath, &st)
	if err != nil {
		return "", err
	}
	isCgroupV2Enabled := st.Type == unix.CGROUP2_SUPER_MAGIC
	if !isCgroupV2Enabled {
		cgroupPath = filepath.Join(cgroupPath, "unified")
	}
	return cgroupPath, nil
}

func (e *EbpfEnricher) CloseBuffer(done <-chan struct{}) {
	<-done
	slog.Debug("cleanly exiting the ebpf enricher")
	e.reader.Close()
}

func (e *EbpfEnricher) Run(done <-chan struct{}, outChan chan<- TcpInfo) {
	slog.Debug("begin reading the ring buffer")

	var rec ringbuf.Record
	var tcpInfo TcpInfo

	go e.CloseBuffer(done)

	for {
		// Blocking reads will be unblocked by closing the reader from
		// underneath the ReadInto call.
		err := e.reader.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			slog.Error("error reading data from the ring buffer", "err", err)
			continue
		}

		if err := tcpInfo.UnmarshalBinary(rec.RawSample); err != nil {
			slog.Warn("error unmarshaling event", "err", err)
		}

		outChan <- tcpInfo
	}
}

func (e *EbpfEnricher) WatchFlow(flow FlowSpec) error {
	return e.coll.Maps[MAP_NAME].Update(flow, 0xFF, ebpf.UpdateAny)
}
