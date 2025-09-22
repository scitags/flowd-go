package marker

import (
	"fmt"
	"strings"

	"github.com/goccy/go-yaml"
)

//go:generate go tool golang.org/x/tools/cmd/stringer -type=Strategy

type Config struct {
	TargetInterfaces   []string `yaml:"targetInterfaces"`
	DiscoverInterfaces bool     `yaml:"discoverInterfaces"`

	RemoveQdisc bool `yaml:"removeQdisc"`

	ProgramPath        string   `yaml:"programPath"`
	RawMarkingStrategy string   `yaml:"markingStrategy"`
	MarkingStrategy    Strategy `yaml:"-"` // Parsed strategy

	DebugMode bool `yaml:"debugMode"`
	MatchAll  bool `yaml:"matchAll"`
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := &config{
		TargetInterfaces:   []string{"lo"},
		DiscoverInterfaces: false,

		RemoveQdisc: true,
		ProgramPath: "",

		RawMarkingStrategy: "label",
		DebugMode:          false,
		MatchAll:           false,
	}

	if err := yaml.Unmarshal(b, def); err != nil {
		return err
	}

	s, ok := ParseStrategy(def.RawMarkingStrategy)
	if !ok {
		return fmt.Errorf("wrong marking strategy %q", def.RawMarkingStrategy)
	}
	def.MarkingStrategy = s

	*c = Config(*def)

	return nil
}

type Strategy int

const (
	Label Strategy = iota
	HopByHop
	Destination
	HopByHopDestination
)

func ParseStrategy(s string) (Strategy, bool) {
	ss, ok := strategyMap[strings.ToLower(s)]
	return ss, ok
}

// strategy map associates available strategies to their string representation.
var strategyMap = func() map[string]Strategy {
	m := make(map[string]Strategy)
	for i := Label; i <= HopByHopDestination; i++ {
		m[strings.ToLower(i.String())] = i
	}
	return m
}()
