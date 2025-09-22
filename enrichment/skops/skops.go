//go:build linux && ebpf

package skops

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/scitags/flowd-go/enrichment"
	"github.com/scitags/flowd-go/internal/progs"
	"github.com/scitags/flowd-go/types"
)

const EBPF_PROGRAM_PATH string = "skops-.bpf.o"

type EbpfEnricher struct {
	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader

	wg *sync.WaitGroup

	cache enrichment.FlowCache
}

func (e *EbpfEnricher) String() string {
	return "eBPF enricher"
}

func (e *EbpfEnricher) Cleanup() error {
	// Note the ringbuff reader is closed by CloseBuffer
	err := e.link.Close()
	e.coll.Close()

	if err != nil {
		return fmt.Errorf("error closing the link: %w", err)
	}

	return nil
}

func NewEnricher(conf *Config) (*EbpfEnricher, error) {
	slog.Debug("initialising the eBPF backend")

	e := EbpfEnricher{}

	var err error
	cgroupPath := ""
	if conf.CgroupPath != "" {
		cgroupPath = conf.CgroupPath
	} else {
		cp, err := GetCgroupInfo()
		if err != nil {
			return nil, fmt.Errorf("couldn't get cgroup information: %w", err)
		}
		cgroupPath = "/sys/fs/cgroup" + cp
	}

	var prog []byte
	if conf.ProgramPath != "" {
		slog.Debug("loading the provided eBPF program", "path", conf.ProgramPath)
		prog, err = os.ReadFile(conf.ProgramPath)
		if err != nil {
			return nil, fmt.Errorf("error reading user provided program: %w", err)
		}
	} else {
		progPath, err := craftProgramPath(conf.Strategy, conf.DebugMode)
		if err != nil {
			return nil, fmt.Errorf("error crafting the embedded program's path: %w", err)
		}
		prog, err = progs.GetSkopsProgram(progPath)
		if err != nil {
			return nil, fmt.Errorf("error choosing an embedded eBPF program: %w", err)
		}
	}

	coll, err := loadProg(prog, conf.PollingInterval)
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

	slog.Debug("attaching program", "cgroup", cgroupPath)
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: e.coll.Programs[PROG_NAME],
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		e.coll.Close()
		return nil, fmt.Errorf("couldn't attach the program to the given cgroup: %w", err)
	}
	e.link = link

	info, err := link.Info()
	if err != nil {
		slog.Warn("error getting link info", "err", err)
	} else {
		slog.Debug("link", "info", info, "iinfo", info.ID)
	}

	// Sync the reader goroutine
	e.wg = &sync.WaitGroup{}

	e.cache = *enrichment.NewFlowCache(10)

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

func (e *EbpfEnricher) closeBuffer(done <-chan struct{}) {
	<-done
	slog.Debug("cleanly exiting the ebpf enricher")
	e.reader.Close()
}

func (e *EbpfEnricher) Run(done <-chan struct{}) {
	slog.Debug("begin reading the ring buffer")

	var rec ringbuf.Record
	var tcpInfo TcpInfo

	go e.closeBuffer(done)

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

		slog.Debug("TCP state info", "oldState", types.State(tcpInfo.State), "newState", types.State(tcpInfo.NewState))

		fi := tcpInfoToFlowInfo(tcpInfo)

		hash := enrichment.HashFlowID(types.FlowID{Src: types.IPPort{Port: uint16(tcpInfo.SrcPort)}, Dst: types.IPPort{Port: uint16(tcpInfo.DstPort)}})

		// Be sure to unlock m on **every** path...
		poller, m, ok := e.cache.GetLock(hash)
		if !ok {
			slog.Warn("got information for nonexistent flow", "hash", hash)
			m.Unlock()
			continue
		}

		poller.DataChan <- &fi

		m.Unlock()
	}
}

func (e *EbpfEnricher) WatchFlow(flowID types.FlowID) (*enrichment.Poller, error) {
	spec := FlowSpec{DstPort: uint32(flowID.Dst.Port), SrcPort: uint32(flowID.Src.Port)}
	if err := e.coll.Maps[MAP_NAME].Update(spec, byte(0xFF), ebpf.UpdateAny); err != nil {
		return nil, fmt.Errorf("error inserting flow spec into eBPF map: %w", err)
	}

	// eBPF samples only contain port numbers (even though they could contain IP addresses too...)
	// Simply drop the IPvX addresses for computing the hashes.
	hash := enrichment.HashFlowID(types.FlowID{Src: types.IPPort{Port: flowID.Src.Port}, Dst: types.IPPort{Port: flowID.Dst.Port}})
	slog.Debug("watching flow", "hash", hash)

	poller, ok := e.cache.Insert(hash, flowID.StartTs)
	if ok {
		slog.Warn("an entry for this flowID already existed", "flowID", flowID)
	}

	go func() {
		slog.Debug("entering polling goroutine", "hash", hash)
		for {
			select {
			case <-poller.DoneChan:
				slog.Debug("cleanly exiting polling goroutine", "hash", hash)
				e.cache.Remove(hash)
				if err := e.coll.Maps[MAP_NAME].Delete(spec); err != nil {
					slog.Warn("error removing flow spec from eBPF map", "err", err)
				}
				return
			}
		}
	}()

	return &poller, nil
}

// Should we simply wait for an
func (e *EbpfEnricher) ForgetFlow(flowID types.FlowID) (time.Time, bool) {
	hash := enrichment.HashFlowID(flowID)
	slog.Debug("marking flow for removal", "hash", hash)
	return e.cache.MarkForRemoval(hash)
}
