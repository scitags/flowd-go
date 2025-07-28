package ebpf

import (
	"strings"
)

type MarkingStrategy string

const (
	FlowLabelMarking           MarkingStrategy = "flowLabel"
	FlowLabelMatchAll          MarkingStrategy = "flowLabelMatchAll"
	HopByHopHeaderMarking      MarkingStrategy = "hopByHop"
	DestinationHeaderMarking   MarkingStrategy = "destination"
	HopByHopDestHeadersMarking MarkingStrategy = "hopByHopAndDestination"
)

var (
	Defaults = map[string]interface{}{
		"targetInterfaces":   []string{"lo"},
		"discoverInterfaces": false,
		"RemoveQdisc":        true,
		"ForceHookRemoval":   true,
		"programPath":        "",
		"markingStrategy":    FlowLabelMarking,
		"debugMode":          false,
	}

	markingStrategyMap = map[string]MarkingStrategy{
		strings.ToLower("flowLabel"):           FlowLabelMarking,
		strings.ToLower("hopByHopHeader"):      HopByHopHeaderMarking,
		strings.ToLower("destinationHeader"):   DestinationHeaderMarking,
		strings.ToLower("hopByHopDestHeaders"): HopByHopDestHeadersMarking,
	}
)

type ebpfBackendMarkingConf struct {
	MarkingStrategy string `json:"markingStrategy"`
}
