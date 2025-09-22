package perfsonar

import "github.com/goccy/go-yaml"

type Config struct {
	ExperimentId int `yaml:"experimentId"`
	ActivityId   int `yaml:"activityId"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		ExperimentId: 0,
		ActivityId:   0,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	*c = Config(*def)

	return nil
}
