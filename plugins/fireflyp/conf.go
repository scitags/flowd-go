package fireflyp

import (
	"github.com/goccy/go-yaml"
)

const (
	minRecvBufferSize uint32 = 2048
)

// FireflyReceiver defines a single UDP destination to forward received fireflies to.
type FireflyReceiver struct {
	Address string `yaml:"address"`
	Port    uint16 `yaml:"port"`
}

type Config struct {
	BindAddress     string `yaml:"bindAddress"`
	BindPort        uint16 `yaml:"bindPort"`
	BufferSize      uint32 `yaml:"bufferSize"`
	Deadline        uint32 `yaml:"deadline"`
	HasSyslogHeader bool   `yaml:"hasSyslogHeader"`
	// FireflyReceivers is an optional list of UDP destinations to relay
	// received firefly datagrams to (e.g. an accounting receiver).
	FireflyReceivers []FireflyReceiver `yaml:"fireflyReceivers"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		BindAddress:      "127.0.0.1",
		BindPort:         10514,
		BufferSize:       2 * minRecvBufferSize,
		Deadline:         0,
		HasSyslogHeader:  false,
		FireflyReceivers: []FireflyReceiver{},
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
