package stun

import (
	"fmt"
	"net/netip"

	"github.com/goccy/go-yaml"
)

type Config struct {
	ManualMapping map[string]string `yaml:"manualMapping"`

	// Internal field
	manualMappingParsed map[netip.Addr]netip.Addr `yaml:"-"`

	StunServers []string `yaml:"stunServers"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		ManualMapping: nil,

		StunServers: []string{
			"stun.l.google.com:3478",
			"stun1.l.google.com:3478",
			"stun2.l.google.com:3478",
			"stun3.l.google.com:3478",
			"stun4.l.google.com:3478",
		},
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	def.manualMappingParsed = map[netip.Addr]netip.Addr{}
	for k, v := range def.ManualMapping {
		kIP, err := netip.ParseAddr(k)
		if err != nil {
			return fmt.Errorf("couldn't parse provided IP address %q", k)
		}

		vIP, err := netip.ParseAddr(v)
		if err != nil {
			return fmt.Errorf("couldn't parse provided IP address %q", v)
		}

		def.manualMappingParsed[kIP] = vIP
	}

	*c = Config(*def)

	return nil
}
