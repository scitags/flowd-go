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

	"github.com/pcolladosoto/glowd"
	"github.com/rjeczalik/notify"
)

const (
	MAX_READERS int = 5
	BUFF_SIZE   int = 1000

	PIPE_PATH string = "np"
)

func Init() error {
	if _, err := os.Stat(PIPE_PATH); !errors.Is(err, os.ErrNotExist) {
		slog.Debug("it looks like the named pipe exists!")
		return nil
	}

	// Consider using the unix package...
	if err := syscall.Mkfifo(PIPE_PATH, 0666); err != nil {
		return fmt.Errorf("couldn't create the named pipe: %w", err)
	}

	return nil
}

func Run(done <-chan struct{}, outChan chan<- glowd.FlowID) {
	pipe, err := os.OpenFile(PIPE_PATH, os.O_RDONLY, os.ModeNamedPipe)
	if err != nil {
		slog.Error("couldn't open the named pipe", "err", err)
		close(outChan)
	}
	defer close(outChan)
	defer pipe.Close()

	// A buffered channel guarantees that we don't loose events even
	// if writes take place at the exact same time
	c := make(chan notify.EventInfo, MAX_READERS)

	// Hook the notifications
	notify.Watch(PIPE_PATH, c, notify.Write|notify.Remove)

	// Listen for events
	buff := make([]byte, BUFF_SIZE)
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
				for _, parsedEvent := range parsedEvents {
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

func Cleanup() error {
	if err := os.Remove(PIPE_PATH); err != nil {
		return fmt.Errorf("error removing named pipe: %w", err)
	}
	return nil
}

func parseEvents(rawEvents string) []glowd.FlowID {
	rawEventsSlice := strings.Split(rawEvents, "\n")
	flowIDs := make([]glowd.FlowID, 0, len(rawEventsSlice))

	// Drop the last entry as it'll always be empty...
	for _, rawEvent := range rawEventsSlice[:len(rawEventsSlice)-1] {
		fields := strings.Fields(rawEvent)
		if len(fields) != 8 {
			slog.Warn("wrong number of fields", "rawEvent", rawEvent)
			continue
		}

		flowState, ok := glowd.ParseFlowState(fields[0])
		if !ok {
			slog.Warn("wrong flow state", "flow state", fields[0])
			continue
		}

		proto, ok := glowd.ParseProtocol(fields[1])
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

		flowID := glowd.FlowID{
			State:      flowState,
			Protocol:   proto,
			Src:        glowd.IPPort{IP: srcIP, Port: uint16(srcPort)},
			Dst:        glowd.IPPort{IP: dstIP, Port: uint16(dstPort)},
			Experiment: fields[6],
			Activity:   fields[7],
		}

		if flowState == glowd.START {
			flowID.StartTs = time.Now()
		} else if flowState == glowd.END {
			flowID.EndTs = time.Now()
		} else {
			slog.Warn("somehow the flow state got mangled", "flowState", flowState.String())
			continue
		}

		flowIDs = append(flowIDs, flowID)
	}

	return flowIDs
}
