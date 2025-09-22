package api

import (
	"github.com/goccy/go-yaml"
)

type Config struct {
	BindAddress string `yaml:"bindAddress"`
	BindPort    uint16 `yaml:"bindPort"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		BindAddress: "127.0.0.1",
		BindPort:    10514,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
