package main

import (
	"fmt"
	"log/slog"

	"github.com/scitags/flowd-go/backends/fireflyb"
	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/backends/prometheus"
	"github.com/scitags/flowd-go/types"
)

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

		if c.Backends.Prometheus != nil {
			b, err := prometheus.NewPrometheusBackend(c.Backends.Prometheus)
			if err != nil {
				return nil, fmt.Errorf("error initialising the prometheus backend: %w", err)
			}
			backends = append(backends, b)
		}
	}

	return backends, nil
}

func cleanupBackends(backends []types.Backend) {
	for _, backend := range backends {
		if err := backend.Cleanup(); err != nil {
			slog.Error("error cleaning up backend", "backend", backend, "err", err)
		}
	}
}
