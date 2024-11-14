//go:build linux && cgo

package ebpf

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MarkingStrategy int

const (
	FlowLabelMarking MarkingStrategy = iota
	HopByHopHeaderMarking
	HopByHopDestHeadersMarking
)

var (
	configurationTags = map[string]bool{
		"targetinterface": false,
		"removeqdisc":     false,
		"programpath":     false,
	}

	DefaultConf = EbpfBackendConf{
		TargetInterface: "lo",
		RemoveQdisc:     true,
		ProgramPath:     "",
		MarkingStrategy: FlowLabelMarking,
		DebugMode:       false,
	}

	markingStrategyMap = map[string]MarkingStrategy{
		strings.ToLower("flowLabel"):           FlowLabelMarking,
		strings.ToLower("hopByHopHeader"):      HopByHopHeaderMarking,
		strings.ToLower("hopByHopDestHeaders"): HopByHopDestHeadersMarking,
	}
)

type EbpfBackendConf struct {
	TargetInterface string          `json:"targetInterface"`
	RemoveQdisc     bool            `json:"removeQdisc"`
	ProgramPath     string          `json:"programPath"`
	MarkingStrategy MarkingStrategy `json:"-"`
	DebugMode       bool            `json:"debugMode"`
}

type ebpfBackendMarkingConf struct {
	MarkingStrategy string `json:"markingStrategy"`
}

// We need an alias to avoid infinite recursion
// in the unmarshalling logic
type AuxEbpfBackendConf EbpfBackendConf

func (c *EbpfBackendConf) UnmarshalJSON(data []byte) error {
	tmp := map[string]interface{}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmp map: %w", err)
	}

	for k := range tmp {
		delete(configurationTags, strings.ToLower(k))
	}

	tmpConf := AuxEbpfBackendConf{}
	if err := json.Unmarshal(data, &tmpConf); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmpConf: %w", err)
	}

	tmpMarkingStrategy := ebpfBackendMarkingConf{}
	if err := json.Unmarshal(data, &tmpMarkingStrategy); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmpMarkingStrategy: %w", err)
	}
	markingStrategy, ok := markingStrategyMap[strings.ToLower(tmpMarkingStrategy.MarkingStrategy)]
	if !ok {
		return fmt.Errorf("wrong marking strategy %s, available ones are %v", tmpMarkingStrategy.MarkingStrategy,
			func() []string {
				markingStrategies := []string{}
				for k := range markingStrategyMap {
					markingStrategies = append(markingStrategies, k)
				}
				return markingStrategies
			}(),
		)
	}
	tmpConf.MarkingStrategy = markingStrategy

	for k := range configurationTags {
		switch strings.ToLower(k) {
		case "targetinterface":
			tmpConf.TargetInterface = DefaultConf.TargetInterface
		case "removeqdisc":
			tmpConf.RemoveQdisc = DefaultConf.RemoveQdisc
		case "programpath":
			tmpConf.ProgramPath = DefaultConf.ProgramPath
		case "markingstrategy":
			tmpConf.MarkingStrategy = DefaultConf.MarkingStrategy
		case "debugmode":
			tmpConf.DebugMode = DefaultConf.DebugMode
		default:
			return fmt.Errorf("unknown configuration key %q", k)
		}
	}

	// Store the results!
	*c = EbpfBackendConf(tmpConf)

	return nil
}
