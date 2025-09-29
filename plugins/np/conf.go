package np

import "github.com/goccy/go-yaml"

type Config struct {
	MaxReaders int    `yaml:"maxReaders"`
	BuffSize   int    `yaml:"buffSize"`
	PipePath   string `yaml:"pipePath"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		MaxReaders: 5,
		BuffSize:   1000,
		PipePath:   "np",
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
