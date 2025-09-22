package fireflyb

import (
	"fmt"

	"github.com/goccy/go-yaml"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
)

type Config struct {
	DestinationPort uint16 `yaml:"destinationPort"`
	PrependSyslog   bool   `yaml:"prependSyslog"`

	SendToCollector  bool   `yaml:"sendToCollector"`
	CollectorAddress string `yaml:"collectorAddress"`
	CollectorPort    int    `yaml:"collectorPort"`

	PeriodicFireflies   bool   `yaml:"periodicFireflies"`
	Period              int    `yaml:"period"`
	EnrichmentVerbosity string `yaml:"enrichmentVerbosity"`

	Netlink *netlink.Config

	SkOps *skops.Config
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		DestinationPort: 10514,
		PrependSyslog:   true,

		SendToCollector:  false,
		CollectorAddress: "127.0.0.1",
		CollectorPort:    10514,

		PeriodicFireflies:   false,
		Period:              1000,
		EnrichmentVerbosity: "lean",

		// Enrichers are unmarshalled by their respective
		// Config implementations.
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	if def.SkOps != nil {
		if def.SkOps.RawStrategy == "" {
			def.SkOps.RawStrategy = skops.DefaultConfig.Strategy.String()
		}

		s, ok := skops.ParseStrategy(def.SkOps.RawStrategy)
		if !ok {
			return fmt.Errorf("wrong enrichment strategy %q", def.SkOps.RawStrategy)
		}
		def.SkOps.Strategy = s

		def.SkOps.PollingInterval = uint64(def.Period) * skops.NS_PER_MS
	}

	if def.Netlink != nil {
		def.Netlink.Period = def.Period
	}

	*c = Config(*def)

	return nil
}
