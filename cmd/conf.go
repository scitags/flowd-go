package main

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/scitags/flowd-go/backends/fireflyb"
	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/backends/prometheus"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
	"github.com/scitags/flowd-go/plugins/api"
	"github.com/scitags/flowd-go/plugins/fireflyp"
	"github.com/scitags/flowd-go/plugins/iperf3"
	"github.com/scitags/flowd-go/plugins/np"
	"github.com/scitags/flowd-go/plugins/perfsonar"
)

type Config struct {
	PidPath string `yaml:"pidPath"`
	WorkDir string `yaml:"workDir"`

	Plugins *struct {
		Np        *np.Config        `yaml:"namedPipe"`
		Firefly   *fireflyp.Config  `yaml:"firefly"`
		Api       *api.Config       `yaml:"api"`
		Perfsonar *perfsonar.Config `yaml:"perfsonar"`
		Iperf3    *iperf3.Config    `yaml:"iperf3"`
	} `yaml:"plugins"`

	Backends *struct {
		Marker     *marker.Config     `yaml:"marker"`
		Firefly    *fireflyb.Config   `yaml:"firefly"`
		Prometheus *prometheus.Config `yaml:"prometheus"`
	} `yaml:"backends"`

	Enrichers *enrichers `yaml:"enrichers"`
}

type enrichers struct {
	Period  *int            `yaml:"period"`
	Netlink *netlink.Config `yaml:"netlink"`
	SkOps   *skops.Config   `yaml:"skops"`
}

func (c Config) String() string {
	m, err := yaml.MarshalWithOptions(c, yaml.Indent(2), yaml.IndentSequence(true))
	if err != nil {
		return "marshalling error..."
	}
	return string(m)
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		PidPath: "/var/run/flowd-go.pid",
		WorkDir: "/var/cache/flowd-go",
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	if def.Enrichers != nil {
		if def.Enrichers.Period == nil {
			f := 1000
			def.Enrichers.Period = &f
		}
		if def.Enrichers.SkOps != nil {
			if def.Enrichers.SkOps.RawStrategy == "" {
				def.Enrichers.SkOps.RawStrategy = skops.DefaultConfig.Strategy.String()
			}

			s, ok := skops.ParseStrategy(def.Enrichers.SkOps.RawStrategy)
			if !ok {
				return fmt.Errorf("wrong enrichment strategy %q", def.Enrichers.SkOps.RawStrategy)
			}
			def.Enrichers.SkOps.Strategy = s

			def.Enrichers.SkOps.PollingInterval = uint64(*def.Enrichers.Period) * skops.NS_PER_MS
		}

		if def.Enrichers.Netlink != nil {
			def.Enrichers.Netlink.Period = *def.Enrichers.Period
		}
	}

	*c = Config(*def)

	return nil
}

func ReadConf(path string) (*Config, error) {
	r, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading the configuration file: %w", err)
	}

	conf := Config{}
	if err := yaml.Unmarshal(r, &conf); err != nil {
		return nil, fmt.Errorf("error unmarshaling the configuration: %w", err)
	}

	return &conf, nil
}
