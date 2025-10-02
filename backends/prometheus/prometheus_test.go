package prometheus

import (
	"log"
	"net/http"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// type metrics struct {
// 	cpuTemp    prometheus.Gauge
// 	hdFailures *prometheus.CounterVec
// }

// func NewMetrics(reg prometheus.Registerer) *metrics {
// 	m := &metrics{
// 		cpuTemp: prometheus.NewGauge(prometheus.GaugeOpts{
// 			Name: "cpu_temperature_celsius",
// 			Help: "Current temperature of the CPU.",
// 		}),
// 		hdFailures: prometheus.NewCounterVec(
// 			prometheus.CounterOpts{
// 				Name: "hd_errors_total",
// 				Help: "Number of hard-disk errors.",
// 			},
// 			[]string{"device"},
// 		),
// 	}
// 	reg.MustRegister(m.cpuTemp)
// 	reg.MustRegister(m.hdFailures)
// 	prometheus.NewGaugeFunc()
// 	return m
// }

func TestMain(t *testing.T) {
	// Create a non-global registry.
	reg := prometheus.NewRegistry()

	// Create new metrics and register them using the custom registry.
	m := newMetrics()

	if err := m.register(reg); err != nil {
		t.Fatalf("error registering the metrics: %v", err)
	}

	// Set values for the new created metrics.
	m.Retrans.With(prometheus.Labels{"foo": "guau"}).Inc()

	// Expose metrics and custom registry via an HTTP server
	// using the HandleFor function. "/metrics" is the usual endpoint for that.
	http.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	log.Fatal(http.ListenAndServe(":8080", nil))
}
