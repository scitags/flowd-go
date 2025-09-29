package main

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/plugins/api"
	"github.com/scitags/flowd-go/plugins/fireflyp"
	"github.com/scitags/flowd-go/plugins/iperf3"
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

		if c.Plugins.Iperf3 != nil {
			p, err := iperf3.NewIperf3Plugin(c.Plugins.Iperf3)
			if err != nil {
				return nil, fmt.Errorf("error initialising the iperf3 plugin: %w", err)
			}
			plugins = append(plugins, p)
		}
	}

	return plugins, nil
}

func cleanupPlugins(plugins []types.Plugin) {
	for _, plugin := range plugins {
		if err := plugin.Cleanup(); err != nil {
			slog.Error("error cleaning up plugin", "plugin", plugin, "err", err)
		}
	}
}
