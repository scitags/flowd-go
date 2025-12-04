package np

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/rjeczalik/notify"
	"github.com/scitags/flowd-go/types"
	glowdTypes "github.com/scitags/flowd-go/types"
)

type NamedPipePlugin struct {
	Config
}

func (p *NamedPipePlugin) String() string {
	return "named pipe"
}

func NewNamedPipePlugin(c *Config) (*NamedPipePlugin, error) {
	p := NamedPipePlugin{Config: *c}

	slog.Debug("initialising the named pipe plugin")

	if _, err := os.Stat(p.PipePath); !errors.Is(err, os.ErrNotExist) {
		slog.Debug("it looks like the named pipe exists!")
		return &p, nil
	}

	oldmask := syscall.Umask(0o000)
	defer syscall.Umask(oldmask)
	// Consider using the unix package...
	if err := syscall.Mkfifo(p.PipePath, 0666); err != nil {
		return nil, fmt.Errorf("couldn't create the named pipe: %w", err)
	}

	return &p, nil
}

func (p *NamedPipePlugin) Run(done <-chan struct{}, outChan chan<- glowdTypes.FlowID) {
	slog.Debug("running the named pipe plugin")

	// If we open the FIFO (i.e. named pipe) only for reading, the call will block
	// until there's at least a writer. This basically means we need to write once
	// to reach the for {} driving the readout of the FIFO. If we instead open
	// the pipe with O_RDWR we are ourselves a writer and so the blocking won't
	// take place. Note the 'correct' approach would be to leverage the O_NONBLOCK
	// flag (i.e. syscall.O_NONBLOCK), but this solution is NOT portable for Darwin.
	// We'd rather not sacrifice portability over this caveat, and so we just
	// open up the FIFO with the O_RDWR flag set and call it a day. Be sure to check
	// https://pubs.opengroup.org/onlinepubs/9799919799/ for a detailed discussion
	// on what O_NONBLOCK implies in terms of behaviour when opening files.
	pipe, err := os.OpenFile(p.PipePath, os.O_RDWR, os.ModeNamedPipe)
	if err != nil {
		slog.Error("couldn't open the named pipe", "err", err)
		close(outChan)
	}
	defer close(outChan)
	defer pipe.Close()

	// A buffered channel guarantees that we don't loose events even
	// if writes take place at the exact same time
	c := make(chan notify.EventInfo, p.MaxReaders)

	// Hook the notifications
	notify.Watch(p.PipePath, c, notify.Write|notify.Remove)

	// Listen for events
	buff := make([]byte, p.BuffSize)
	for {
		select {
		case e := <-c:
			switch e.Event() {
			case notify.Write:
				n, err := pipe.Read(buff)
				if err != nil {
					slog.Warn("error reading pipe", "err", err)
				}
				slog.Debug("read pipe", "n", n, "buff", buff[:n])
				parsedEvents := parseEvents(string(buff[:n]))
				for i, parsedEvent := range parsedEvents {
					slog.Debug("pushing event onto channel", "i", i)
					outChan <- parsedEvent
				}
			case notify.Remove:
				slog.Error("the named pipe was removed from under us!")
				return
			}
		case <-done:
			slog.Debug("cleanly exiting the np plugin")
			return
		}
	}
}

func (p *NamedPipePlugin) Cleanup() error {
	slog.Debug("cleaning up the named pipe plugin")
	if err := os.Remove(p.PipePath); err != nil {
		return fmt.Errorf("error removing named pipe: %w", err)
	}
	return nil
}

func parseEvents(rawEvents string) []glowdTypes.FlowID {
	rawEventsSlice := strings.Split(rawEvents, "\n")
	flowIDs := make([]glowdTypes.FlowID, 0, len(rawEventsSlice))

	// Drop the last entry as it'll always be empty...
	for _, rawEvent := range rawEventsSlice[:len(rawEventsSlice)-1] {
		fields := strings.Fields(rawEvent)
		if len(fields) != 8 {
			slog.Warn("wrong number of fields", "rawEvent", rawEvent)
			continue
		}

		flowState, ok := glowdTypes.ParseFlowState(fields[0])
		if !ok {
			slog.Warn("wrong flow state", "flow state", fields[0])
			continue
		}

		proto, ok := glowdTypes.ParseProtocol(fields[1])
		if !ok {
			slog.Warn("wrong protocol", "protocol", fields[1])
			continue
		}

		srcIP := net.ParseIP(fields[2])
		if srcIP == nil {
			slog.Warn("wrong source IP address", "srcIP", fields[2])
			continue
		}

		srcPort, err := strconv.ParseUint(fields[3], 10, 16)
		if err != nil {
			slog.Warn("wrong source port", "srcPort", fields[3])
			continue
		}

		dstIP := net.ParseIP(fields[4])
		if dstIP == nil {
			slog.Warn("wrong destination IP address", "dstIP", fields[4])
			continue
		}

		dstPort, err := strconv.ParseUint(fields[5], 10, 16)
		if err != nil {
			slog.Warn("wrong destination port", "srcPort", fields[5])
			continue
		}

		experimentId, err := strconv.ParseUint(fields[6], 10, 32)
		if err != nil {
			slog.Warn("wrong experiment ID", "experimentId", fields[6])
			continue
		}

		activityId, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			slog.Warn("wrong activity ID", "activityId", fields[7])
			continue
		}

		if types.IsIPv4(srcIP) != types.IsIPv4(dstIP) {
			slog.Warn("found different IP address families", "srcIP IPv4?", types.IsIPv4(srcIP), "dstIP IPv4?", types.IsIPv4(dstIP))
		}

		flowID := glowdTypes.FlowID{
			State:    flowState,
			Protocol: proto,
			Family: func() types.Family {
				if types.IsIPv4(srcIP) {
					return types.IPv4
				}
				return types.IPv6
			}(),
			Src:         glowdTypes.IPPort{IP: srcIP, Port: uint16(srcPort)},
			Dst:         glowdTypes.IPPort{IP: dstIP, Port: uint16(dstPort)},
			Experiment:  uint32(experimentId),
			Activity:    uint32(activityId),
			Application: types.SYSLOG_APP_NAME,
		}

		if flowState == glowdTypes.START {
			flowID.StartTs = time.Now()
		} else if flowState == glowdTypes.END {
			flowID.EndTs = time.Now()
		} else {
			slog.Warn("somehow the flow state got mangled", "flowState", flowState.String())
			continue
		}

		flowIDs = append(flowIDs, flowID)
	}

	return flowIDs
}
