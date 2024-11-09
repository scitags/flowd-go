package main

import (
	"fmt"
	"log/slog"

	glowd "github.com/scitags/flowd-go"
	"github.com/scitags/flowd-go/backends/ebpf"
	"github.com/scitags/flowd-go/backends/firefly"
	"github.com/scitags/flowd-go/plugins/api"
	"github.com/scitags/flowd-go/plugins/np"
	"github.com/scitags/flowd-go/settings"
)

func createPlugins(conf settings.Config) ([]glowd.Plugin, error) {
	plugins := make([]glowd.Plugin, 0, len(conf.Plugins))

	for _, v := range conf.Plugins {
		switch c := v.(type) {
		case np.NamedPipePluginConf:
			plugins = append(plugins, np.New(&c))
		case api.ApiPluginConf:
			plugins = append(plugins, api.New(&c))
		default:
			return nil, fmt.Errorf("unknown plugin type for %q", v)
		}
	}

	for _, plugin := range plugins {
		if err := plugin.Init(); err != nil {
			return nil, fmt.Errorf("error setting up plugin %q: %w", plugin, err)
		}
	}

	return plugins, nil
}

func cleanupPlugins(plugins []glowd.Plugin) {
	for _, plugin := range plugins {
		if err := plugin.Cleanup(); err != nil {
			slog.Error("error cleaning up plugin", "plugin", plugin, "err", err)
		}
	}
}

func createBackends(conf settings.Config) ([]glowd.Backend, error) {
	backends := make([]glowd.Backend, 0, len(conf.Backends))
	// backends := make([]glowd.Backend, 0, len(conf.Backends))
	for _, v := range conf.Backends {
		switch c := v.(type) {
		case ebpf.EbpfBackendConf:
			backends = append(backends, ebpf.New(&c))
		case firefly.FireflyBackendConf:
			backends = append(backends, firefly.New(&c))
		default:
			return nil, fmt.Errorf("unknown plugin type for %q", v)
		}
	}

	for _, backend := range backends {
		if err := backend.Init(); err != nil {
			return nil, fmt.Errorf("error setting up backend %q: %w", backend, err)
		}
	}

	return backends, nil
}

func cleanupBackends(backends []glowd.Backend) {
	for _, backend := range backends {
		if err := backend.Cleanup(); err != nil {
			slog.Error("error cleaning up backend", "backend", backend, "err", err)
		}
	}
}
