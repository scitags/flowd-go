package main

import (
	"fmt"
	"log/slog"
	"net"
	"path/filepath"

	glowd "github.com/scitags/flowd-go"
	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/plugins/perfsonar"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func initPlugins(plugins []glowdTypes.Plugin) error {
	for _, plugin := range plugins {
		if err := plugin.Init(); err != nil {
			return fmt.Errorf("error setting up plugin %s: %w", plugin, err)
		}
	}
	return nil
}

func initBackends(backends []glowdTypes.Backend) error {
	for _, backend := range backends {
		if err := backend.Init(); err != nil {
			return fmt.Errorf("error setting up backend %s: %w", backend, err)
		}
	}
	return nil
}

// Are there any plugin-backend dependencies we should be aware of?
func pluginBackendDependencies(plugins []glowdTypes.Plugin, backends []glowdTypes.Backend) error {
	for _, plugin := range plugins {
		switch plugin.(type) {
		case *perfsonar.PerfsonarPlugin:
			for _, backend := range backends {
				markerBackend, ok := backend.(*marker.MarkerBackend)
				if !ok {
					continue
				}
				slog.Warn("overriding marking strategy for the eBPF backend",
					"previous", markerBackend.MarkingStrategy, "new", marker.Label, "matchAll", true)
				markerBackend.MarkingStrategy = string(marker.Label)
				markerBackend.MatchAll = true
			}
		// Do nothing on default, just be exhaustive :P
		default:
		}
	}
	return nil
}

func cleanupPlugins(plugins []glowdTypes.Plugin) {
	for _, plugin := range plugins {
		if err := plugin.Cleanup(); err != nil {
			slog.Error("error cleaning up plugin", "plugin", plugin, "err", err)
		}
	}
}

func cleanupBackends(backends []glowdTypes.Backend) {
	for _, backend := range backends {
		if err := backend.Cleanup(); err != nil {
			slog.Error("error cleaning up backend", "backend", backend, "err", err)
		}
	}
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
	if a.Key == glowd.FlowTagKey {
		// When slog gobbles the flow tag it becomes a uint64 instead of a uint32
		// apparently...
		flowLabel, ok := a.Value.Any().(uint64)
		if ok {
			return slog.Attr{Key: a.Key, Value: slog.StringValue(fmt.Sprintf("%#x;(%#020b)", flowLabel, flowLabel))}
		}
	}

	// Format the flow hashes
	if a.Key == glowd.FlowHashKey {
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
