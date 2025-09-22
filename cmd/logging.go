package main

import (
	"fmt"
	"log/slog"
	"net"
	"path/filepath"

	"github.com/scitags/flowd-go/backends/marker"
)

const (
	FlowTagKey  string = "flowTag"
	FlowHashKey string = "flowHash"
)

var logLevelMap = map[string]slog.Level{
	"debug": slog.LevelDebug,
	"info":  slog.LevelInfo,
	"warn":  slog.LevelWarn,
	"error": slog.LevelError,
}

func logReplacements(groups []string, a slog.Attr) slog.Attr {
	// Remove time.
	if a.Key == slog.TimeKey && len(groups) == 0 && !logTimeFlag {
		return slog.Attr{}
	}

	// Remove the directory from the source's filename.
	if a.Key == slog.SourceKey {
		source := a.Value.Any().(*slog.Source)
		source.File = filepath.Base(source.File)
	}

	// Format the flow tag as both a binary and hex number
	if a.Key == FlowTagKey {
		// When slog gobbles the flow tag it becomes a uint64 instead of a uint32
		// apparently...
		flowLabel, ok := a.Value.Any().(uint64)
		if ok {
			return slog.Attr{Key: a.Key, Value: slog.StringValue(fmt.Sprintf("%#x;(%#020b)", flowLabel, flowLabel))}
		}
	}

	// Format the flow hashes
	if a.Key == FlowHashKey {
		flowHash, ok := a.Value.Any().(marker.FlowFourTuple)
		if ok {
			return slog.Attr{Key: a.Key, Value: slog.StringValue(
				fmt.Sprintf("%s(%#x|%#x);%d;%d", net.IP([]byte{
					byte(flowHash.IPv6Hi & (0xFF << 7) >> 7),
					byte(flowHash.IPv6Hi & (0xFF << 6) >> 6),
					byte(flowHash.IPv6Hi & (0xFF << 5) >> 5),
					byte(flowHash.IPv6Hi & (0xFF << 4) >> 4),
					byte(flowHash.IPv6Hi & (0xFF << 3) >> 3),
					byte(flowHash.IPv6Hi & (0xFF << 2) >> 2),
					byte(flowHash.IPv6Hi & (0xFF << 1) >> 1),
					byte(flowHash.IPv6Hi & 0xFF),
					byte(flowHash.IPv6Lo & (0xFF << 7) >> 7),
					byte(flowHash.IPv6Lo & (0xFF << 6) >> 6),
					byte(flowHash.IPv6Lo & (0xFF << 5) >> 5),
					byte(flowHash.IPv6Lo & (0xFF << 4) >> 4),
					byte(flowHash.IPv6Lo & (0xFF << 3) >> 3),
					byte(flowHash.IPv6Lo & (0xFF << 2) >> 2),
					byte(flowHash.IPv6Lo & (0xFF << 1) >> 1),
					byte(flowHash.IPv6Lo & 0xFF),
				}), flowHash.IPv6Hi, flowHash.IPv6Lo, flowHash.SrcPort, flowHash.DstPort),
			)}
		}
	}

	return a
}
