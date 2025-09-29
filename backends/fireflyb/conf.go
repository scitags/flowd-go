package fireflyb

import (
	"github.com/goccy/go-yaml"
)

type Config struct {
	DestinationPort uint16 `yaml:"destinationPort"`
	PrependSyslog   bool   `yaml:"prependSyslog"`

	SendToCollector  bool   `yaml:"sendToCollector"`
	CollectorAddress string `yaml:"collectorAddress"`
	CollectorPort    int    `yaml:"collectorPort"`

	Enrich              bool   `yaml:"periodicFireflies"`
	EnrichmentVerbosity string `yaml:"enrichmentVerbosity"`
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

		Enrich:              false,
		EnrichmentVerbosity: "lean",
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
