//go:build linux && cgo

package ebpf

import (
	"strings"
)

type MarkingStrategy string

const (
	FlowLabelMarking           MarkingStrategy = "flowLabel"
	FlowLabelMatchAll          MarkingStrategy = "flowLabelMatchAll"
	HopByHopHeaderMarking      MarkingStrategy = "hopByHop"
	HopByHopDestHeadersMarking MarkingStrategy = "hopByHopAndDestination"
)

var (
	Defaults = map[string]interface{}{
		"targetInterface":  "lo",
		"RemoveQdisc":      true,
		"ForceHookRemoval": true,
		"programPath":      "",
		"markingStrategy":  FlowLabelMarking,
		"debugMode":        false,
	}

	markingStrategyMap = map[string]MarkingStrategy{
		strings.ToLower("flowLabel"):           FlowLabelMarking,
		strings.ToLower("hopByHopHeader"):      HopByHopHeaderMarking,
		strings.ToLower("hopByHopDestHeaders"): HopByHopDestHeadersMarking,
	}
)

type ebpfBackendMarkingConf struct {
	MarkingStrategy string `json:"markingStrategy"`
}
