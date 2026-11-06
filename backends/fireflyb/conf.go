package fireflyb

import (
	"github.com/goccy/go-yaml"
	"github.com/scitags/flowd-go/internal/stun"
)

type Config struct {
	DestinationPort uint16 `yaml:"destinationPort"`
	PrependSyslog   bool   `yaml:"prependSyslog"`

	SendToCollector  bool   `yaml:"sendToCollector"`
	CollectorAddress string `yaml:"collectorAddress"`
	CollectorPort    int    `yaml:"collectorPort"`

	Enrich         bool   `yaml:"enrich"`
	EnrichmentMode string `yaml:"enrichmentMode"`

	Stun *stun.Config `yaml:"stun"`

	// Whether to skip periodic fireflies
	OnlyEnd bool `yaml:"-"`
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

		Enrich:         false,
		EnrichmentMode: "lean",

		OnlyEnd: false,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	// We'll skip periodic fireflies when running in usage mode
	def.OnlyEnd = def.EnrichmentMode == "usage"

	*c = Config(*def)

	return nil
}
