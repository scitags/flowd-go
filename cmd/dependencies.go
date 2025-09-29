package main

import (
	"log/slog"

	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/plugins/perfsonar"
	"github.com/scitags/flowd-go/types"
)

// Are there any plugin-backend dependencies we should be aware of?
func pluginBackendDependencies(plugins []types.Plugin, backends []types.Backend) error {
	for _, plugin := range plugins {
		switch plugin.(type) {
		case *perfsonar.PerfsonarPlugin:
			for _, backend := range backends {
				markerBackend, ok := backend.(*marker.MarkerBackend)
				if !ok {
					continue
				}
				slog.Warn("overriding marking criteria to match all for the marker backend")
				markerBackend.MatchAll = true
			}
		// Do nothing by default, just be exhaustive :P
		default:
		}
	}
	return nil
}
