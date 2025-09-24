package iperf3

import "github.com/goccy/go-yaml"

type Config struct {
	MinSourcePort int `yaml:"minSourcePort"`
	MaxSourcePort int `yaml:"maxSourcePort"`

	MinDestinationPort int `yaml:"minDestinationPort"`
	MaxDestinationPort int `yaml:"maxDestinationPort"`

	CgroupPath  string `yaml:"cgroupPath"`
	ProgramPath string `yaml:"programPath"`

	DebugMode bool `yaml:"debugMode"`

	RandomIDs     bool  `yaml:"randomIDs"`
	ActivityIDs   []int `yaml:"activityIDs"`
	ExperimentIDs []int `yaml:"experimentIDs"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		MinSourcePort: 0,
		MaxSourcePort: 0,

		MinDestinationPort: 0,
		MaxDestinationPort: 0,

		CgroupPath:  "/sys/fs/cgroup",
		ProgramPath: "",

		DebugMode: false,

		RandomIDs:     false,
		ActivityIDs:   []int{0, 1, 2},
		ExperimentIDs: []int{0, 1, 2},
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
