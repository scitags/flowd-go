package stun

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/goccy/go-yaml"
)

type Config struct {
	ManualMapping map[string]string `yaml:"manualMapping"`

	// Internal field
	manualMappingParsed map[netip.Addr]net.IP `yaml:"-"`

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

	def.manualMappingParsed = map[netip.Addr]net.IP{}
	for k, v := range def.ManualMapping {
		rawIP := net.ParseIP(k)
		if rawIP == nil {
			return fmt.Errorf("couldn't parse provided IP address %q", k)
		}

		ip, err := netip.ParseAddr(k)
		if err != nil {
			return fmt.Errorf("couldn't parse provided IP address %q: %w", k, err)
		}

		rawIP = net.ParseIP(v)
		if rawIP == nil {
			return fmt.Errorf("couldn't parse provided IP address %q", k)
		}

		def.manualMappingParsed[ip] = rawIP
	}

	*c = Config(*def)

	return nil
}
