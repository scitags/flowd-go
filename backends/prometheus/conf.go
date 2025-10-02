package prometheus

import (
	"github.com/goccy/go-yaml"
)

type Config struct {
	Log         bool   `yaml:"log"`
	BindAddress string `yaml:"bindAddress"`
	NetlinkPort uint16 `yaml:"netlinkPort"`
	SkopsPort   uint16 `yaml:"skopsPort"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		Log:         true,
		BindAddress: "127.0.0.1",
		NetlinkPort: 8080,
		SkopsPort:   8081,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
