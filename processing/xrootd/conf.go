package xrootd

import (
	"github.com/goccy/go-yaml"
)

const (
	minRecvBufferSize uint32 = 2048
)

type Config struct {
	BindAddress string `yaml:"bindAddress"`
	BindPort    uint16 `yaml:"bindPort"`
	BufferSize  uint32 `yaml:"bufferSize"`
	Deadline    uint32 `yaml:"deadline"`

	CacheTTL uint32 `yaml:"cacheTTL"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		BindAddress: "127.0.01.",
		BindPort:    10514,
		BufferSize:  2 * minRecvBufferSize,
		Deadline:    0,

		CacheTTL: 60,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
