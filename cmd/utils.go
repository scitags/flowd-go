package main

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/backends/fireflyb"
	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/plugins/api"
	"github.com/scitags/flowd-go/plugins/fireflyp"
	"github.com/scitags/flowd-go/plugins/np"
	"github.com/scitags/flowd-go/plugins/perfsonar"
	"github.com/scitags/flowd-go/types"
)

func createPlugins(c *Config) ([]types.Plugin, error) {
	plugins := []types.Plugin{}

	if c.Plugins != nil {
		if c.Plugins.Api != nil {
			p, err := api.NewApiPlugin(c.Plugins.Api)
			if err != nil {
				return nil, fmt.Errorf("error initialising the api plugin: %w", err)
			}
			plugins = append(plugins, p)
		}

		if c.Plugins.Firefly != nil {
			p, err := fireflyp.NewFireflyPlugin(c.Plugins.Firefly)
			if err != nil {
				return nil, fmt.Errorf("error initialising the firefly plugin: %w", err)
			}
			plugins = append(plugins, p)
		}

		if c.Plugins.Np != nil {
			p, err := np.NewNamedPipePlugin(c.Plugins.Np)
			if err != nil {
				return nil, fmt.Errorf("error initialising the perfsonar plugin: %w", err)
			}
			plugins = append(plugins, p)
		}

		if c.Plugins.Perfsonar != nil {
			p, err := perfsonar.NewPerfsonarPlugin(c.Plugins.Perfsonar)
			if err != nil {
				return nil, fmt.Errorf("error initialising the perfsonar plugin: %w", err)
			}
			plugins = append(plugins, p)
		}
	}

	return plugins, nil
}

func createBackends(c *Config) ([]types.Backend, error) {
	backends := []types.Backend{}

	if c.Backends != nil {
		if c.Backends.Marker != nil {
			b, err := marker.NewMarkerBackend(c.Backends.Marker)
			if err != nil {
				return nil, fmt.Errorf("error initialising the marker backend: %w", err)
			}
			backends = append(backends, b)
		}

		if c.Backends.Firefly != nil {
			b, err := fireflyb.NewFireflyBackend(c.Backends.Firefly)
			if err != nil {
				return nil, fmt.Errorf("error initialising the firefly backend: %w", err)
			}
			backends = append(backends, b)
		}
	}

	return backends, nil
}

func initPlugins(plugins []types.Plugin) error {
	for _, plugin := range plugins {
		if err := plugin.Init(); err != nil {
			return fmt.Errorf("error setting up plugin %s: %w", plugin, err)
		}
	}
	return nil
}

func initBackends(backends []types.Backend) error {
	for _, backend := range backends {
		if err := backend.Init(); err != nil {
			return fmt.Errorf("error setting up backend %s: %w", backend, err)
		}
	}
	return nil
}

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
				slog.Warn("overriding marking strategy for the eBPF backend",
					"previous", markerBackend.MarkingStrategy, "new", marker.Label, "matchAll", true)
				markerBackend.MarkingStrategy = marker.Label
				markerBackend.MatchAll = true
			}
		// Do nothing by default, just be exhaustive :P
		default:
		}
	}
	return nil
}

func cleanupPlugins(plugins []types.Plugin) {
	for _, plugin := range plugins {
		if err := plugin.Cleanup(); err != nil {
			slog.Error("error cleaning up plugin", "plugin", plugin, "err", err)
		}
	}
}

func cleanupBackends(backends []types.Backend) {
	for _, backend := range backends {
		if err := backend.Cleanup(); err != nil {
			slog.Error("error cleaning up backend", "backend", backend, "err", err)
		}
	}
}
