package main

import (
	"fmt"
	"os"

	"github.com/goccy/go-yaml"
	"github.com/scitags/flowd-go/backends/fireflyb"
	"github.com/scitags/flowd-go/backends/marker"
	"github.com/scitags/flowd-go/plugins/api"
	"github.com/scitags/flowd-go/plugins/fireflyp"
	"github.com/scitags/flowd-go/plugins/np"
	"github.com/scitags/flowd-go/plugins/perfsonar"
)

type Config struct {
	PidPath     string   `yaml:"pidPath"`
	WorkDir     string   `yaml:"workDir"`
	StunServers []string `yaml:"stunServers"`

	Plugins *struct {
		Np        *np.Config        `yaml:"namedPipe"`
		Firefly   *fireflyp.Config  `yaml:"firefly"`
		Api       *api.Config       `yaml:"api"`
		Perfsonar *perfsonar.Config `yaml:"perfsonar"`
	} `yaml:"plugins"`

	Backends *struct {
		Marker  *marker.Config   `yaml:"marker"`
		Firefly *fireflyb.Config `yaml:"firefly"`
	} `yaml:"backends"`
}

func (c Config) String() string {
	m, err := yaml.MarshalWithOptions(c, yaml.Indent(2), yaml.IndentSequence(true))
	if err != nil {
		return "marshalling error..."
	}
	return string(m)
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		PidPath:     "/var/run/flowd-go.pid",
		WorkDir:     "/var/cache/flowd-go",
		StunServers: []string{},
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}

func ReadConf(path string) (*Config, error) {
	r, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading the configuration file: %w", err)
	}

	conf := Config{}
	if err := yaml.Unmarshal(r, &conf); err != nil {
		return nil, fmt.Errorf("error unmarshaling the configuration: %w", err)
	}

	return &conf, nil
}
