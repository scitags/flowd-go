package prometheus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/scitags/flowd-go/types"
)

var logger *slog.Logger

type PrometheusBackend struct {
	Config

	m       map[types.Flavour]*metrics
	servers []*http.Server
}

func (b *PrometheusBackend) String() string {
	return "Prometheus"
}

func NewPrometheusBackend(c *Config) (*PrometheusBackend, error) {
	if c.Log {
		logger = slog.Default().With("t", "prometheus")
	} else {
		logger = slog.New(slog.DiscardHandler)
	}

	logger.Debug("initialising the prometheus backend")

	b := PrometheusBackend{Config: *c}

	b.m = map[types.Flavour]*metrics{}

	if b.NetlinkPort == 0 && b.SkopsPort == 0 {
		slog.Warn("both metric flavours are disabled")
	}

	if b.NetlinkPort != 0 {
		// Create a non-global registry.
		reg := prometheus.NewRegistry()

		b.m[types.Netlink] = newMetrics()

		if err := b.m[types.Netlink].register(reg); err != nil {
			return nil, fmt.Errorf("error registering the metrics: %v", err)
		}

		handler := http.NewServeMux()
		handler.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))

		b.servers = append(b.servers, &http.Server{
			Addr:    fmt.Sprintf("%s:%d", b.BindAddress, b.NetlinkPort),
			Handler: handler,
		})
	}

	if b.SkopsPort != 0 {
		// Create a non-global registry.
		reg := prometheus.NewRegistry()

		b.m[types.Ebpf] = newMetrics()

		if err := b.m[types.Ebpf].register(reg); err != nil {
			return nil, fmt.Errorf("error registering the metrics: %v", err)
		}

		handler := http.NewServeMux()
		handler.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))

		b.servers = append(b.servers, &http.Server{
			Addr:    fmt.Sprintf("%s:%d", b.BindAddress, b.SkopsPort),
			Handler: handler,
		})
	}

	return &b, nil
}

func (b *PrometheusBackend) Run(done <-chan struct{}, inChan <-chan types.FlowID) {
	logger.Debug("running the prometheus backend")

	// Start the servers!
	for _, server := range b.servers {
		go func() {
			if err := server.ListenAndServe(); err != nil {
				logger.Info("stopped listening", "err", err)
			}
		}()
	}

	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				logger.Warn("somebody closed the input channel!")
				return
			}
			logger.Debug("got a flowID", "flowID", flowID)

			switch flowID.State {
			case types.START:
				for t, fc := range flowID.FlowInfoChans {
					if fc == nil {
						continue
					}
					go b.periodicUpdate(flowID, t, fc)
				}
			}
		case <-done:
			logger.Debug("cleanly exiting the prometheus backend")
			return
		}
	}
}

func (b *PrometheusBackend) Cleanup() error {
	logger.Debug("cleaning up the prometheus backend")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var errs error
	for _, server := range b.servers {
		if err := server.Shutdown(ctx); err != nil {
			errs = errors.Join(err)
		}
	}

	return errs
}

func (b *PrometheusBackend) periodicUpdate(f types.FlowID, flavour types.Flavour, fic chan *types.FlowInfo) {
	logger.Debug("starting periodic prometheus goroutine", "flowID", f, "flavour", flavour)

	labels := b.m[flavour].newLabels(f, flavour)

	for fi := range fic {
		b.m[flavour].update(labels, fi)
	}

	logger.Debug("removing metrics", "flowID", f, "flavour", flavour)
	b.m[flavour].delete(labels)

	logger.Debug("exiting periodic prometheus goroutine", "flowID", f)
}
