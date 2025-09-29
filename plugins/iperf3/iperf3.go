//go:build ebpf

package iperf3

import (
	"errors"
	"fmt"
	"log"
	"log/slog"
	"math/rand/v2"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/containerd/cgroups"
	"github.com/prometheus/procfs"
	"github.com/scitags/flowd-go/internal/progs"
	"github.com/scitags/flowd-go/types"
)

type flowSpec struct {
	Family uint64

	SIpHi uint64
	SIpLo uint64
	SPort uint32

	DIpHi uint64
	DIpLo uint64
	DPort uint32
}

type Iperf3Plugin struct {
	Config

	coll   *ebpf.Collection
	link   link.Link
	reader *ringbuf.Reader
}

func NewIperf3Plugin(c *Config) (*Iperf3Plugin, error) {
	p := Iperf3Plugin{Config: *c}

	if len(c.ExperimentIDs) != len(c.ActivityIDs) {
		return nil, fmt.Errorf("experimentIDs and activityIDs have different lengths")
	}

	if len(c.ExperimentIDs) == 0 || len(c.ActivityIDs) == 0 {
		return nil, fmt.Errorf("experimentIDs or activityIDs are empty")
	}

	var err error
	cgroupPath := ""
	if c.CgroupPath != "" {
		cgroupPath = c.CgroupPath
	} else {
		cp, err := GetCgroupInfo()
		if err != nil {
			return nil, fmt.Errorf("couldn't get cgroup information: %w", err)
		}
		cgroupPath = "/sys/fs/cgroup" + cp
	}

	var prog []byte
	if c.ProgramPath != "" {
		slog.Debug("loading the provided eBPF program", "path", c.ProgramPath)
		prog, err = os.ReadFile(c.ProgramPath)
		if err != nil {
			return nil, fmt.Errorf("error reading user provided program: %w", err)
		}
	} else {
		progPath, err := craftProgramPath(c.DebugMode)
		if err != nil {
			return nil, fmt.Errorf("error crafting the embedded program's path: %w", err)
		}
		prog, err = progs.GetWatcherProgram(progPath)
		if err != nil {
			return nil, fmt.Errorf("error choosing an embedded eBPF program: %w", err)
		}
	}

	coll, err := loadProg(prog, c)
	if err != nil {
		return nil, fmt.Errorf("error loading the eBPF program: %w", err)
	}
	p.coll = coll

	rd, err := ringbuf.NewReader(coll.Maps[RINGBUFF_NAME])
	if err != nil {
		p.coll.Close()
		return nil, fmt.Errorf("error setting up the ringbuffer reader: %w", err)
	}
	p.reader = rd

	slog.Debug("attaching program", "cgroup", cgroupPath)
	link, err := link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Program: p.coll.Programs[PROG_NAME],
		Attach:  ebpf.AttachCGroupSockOps,
	})
	if err != nil {
		p.coll.Close()
		return nil, fmt.Errorf("couldn't attach the program to the given cgroup: %w", err)
	}
	p.link = link

	info, err := link.Info()
	if err != nil {
		slog.Warn("error getting link info", "err", err)
	} else {
		slog.Debug("link", "info", info, "iinfo", info.ID)
	}

	return &p, nil
}

func (p *Iperf3Plugin) String() string {
	return "iperf3"
}

func (p *Iperf3Plugin) Init() error {
	slog.Debug("initialising the iperf3 plugin")
	return nil
}

func (p *Iperf3Plugin) closeBuffer(done <-chan struct{}) {
	<-done
	slog.Debug("closing the ring buffer")
	p.reader.Close()
}

func parsePort(r []byte) uint16 {
	return uint16(r[1])<<8 | uint16(r[0])
}

func parseIP(f types.Family, r []byte) net.IP {
	switch f {
	case types.IPv4:
		return net.IP([]byte{
			r[11], r[10], r[9], r[8],
		})
	case types.IPv6:
		return net.IP([]byte{
			r[7], r[6], r[5], r[4], r[3], r[2], r[1], r[0],
			r[15], r[14], r[13], r[12], r[11], r[10], r[9], r[8],
		})
	}
	return nil
}

func (p *Iperf3Plugin) Run(done <-chan struct{}, outChan chan<- types.FlowID) {
	slog.Debug("running the iperf3 plugin")

	var rec ringbuf.Record

	go p.closeBuffer(done)
	defer close(outChan)

	idIndex := 0
	if p.RandomIDs {
		idIndex = rand.IntN(len(p.ExperimentIDs))
	}

	for {
		// Blocking reads will be unblocked by closing the reader from
		// underneath the ReadInto call.
		err := p.reader.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("received signal, exiting..")
				return
			}
			slog.Error("error reading data from the ring buffer", "err", err)
			continue
		}

		if len(rec.RawSample) != 64 {
			slog.Warn("received data length is not correct", "len", len(rec.RawSample))
			continue
		}

		var s types.FlowState
		switch types.State(rec.RawSample[56]) {
		case types.TCP_ESTABLISHED:
			s = types.START
		case types.TCP_CLOSE:
			s = types.END
		default:
			slog.Warn("unexpected state", "s", rec.RawSample[56])
		}

		family := types.Family(rec.RawSample[0])
		f := types.FlowID{
			State:  s,
			Family: family,
			Src: types.IPPort{
				IP:   parseIP(family, rec.RawSample[8:24]),
				Port: parsePort(rec.RawSample[24:32]),
			},
			Dst: types.IPPort{
				IP:   parseIP(family, rec.RawSample[32:48]),
				Port: parsePort(rec.RawSample[48:56]),
			},
			Experiment: uint32(p.ExperimentIDs[idIndex]),
			Activity:   uint32(p.ActivityIDs[idIndex]),
		}
		slog.Debug("crafted flowID", "flowID", f)

		if p.RandomIDs {
			idIndex = rand.IntN(len(p.ExperimentIDs))
		} else {
			idIndex = (idIndex + 1) % len(p.ExperimentIDs)
		}

		outChan <- f
	}
}

func (p *Iperf3Plugin) Cleanup() error {
	slog.Debug("cleaning up the iperf3 plugin")
	// Note the ringbuff reader is closed by CloseBuffer
	err := p.link.Close()
	p.coll.Close()

	if err != nil {
		return fmt.Errorf("error closing the link: %w", err)
	}

	return nil
}

func GetCgroupInfo() (string, error) {
	if cgroups.Mode() != cgroups.Unified {
		return "", fmt.Errorf("running with cgroup mode %d, want %d", cgroups.Mode(), cgroups.Unified)
	}

	procPID := os.Getpid()
	proc, err := procfs.NewProc(procPID)
	if err != nil {
		return "", fmt.Errorf("error getting proc entry for PID %d: %w", procPID, err)
	}

	cgroups, err := proc.Cgroups()
	if err != nil {
		return "", fmt.Errorf("error getting cgroup information: %w", err)
	}

	for i, cgroup := range cgroups {
		slog.Debug("cgroup", "i", i, "cgroup", cgroup)
	}

	if len(cgroups) == 0 {
		return "", fmt.Errorf("the process belongs to no cgroups: we can't handle it")
	}

	if len(cgroups) > 1 {
		return "", fmt.Errorf("the process belongs to more than one cgroup: we can't handle it")
	}

	cgroupPath := strings.Split(cgroups[0].Path, "/")

	return strings.Join(cgroupPath[:len(cgroupPath)-1], "/"), nil
}
