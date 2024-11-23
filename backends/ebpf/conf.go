//go:build linux && cgo

package ebpf

import (
	"strings"
)

type MarkingStrategy string

const (
	FlowLabelMarking           MarkingStrategy = "flowLabel"
	HopByHopHeaderMarking      MarkingStrategy = "hopByHop"
	HopByHopDestHeadersMarking MarkingStrategy = "hopByHopAndDestination"
)

var (
	Defaults = map[string]interface{}{
		"targetInterface": "lo",
		"RemoveQdisc":     true,
		"programPath":     "",
		"markingStrategy": FlowLabelMarking,
		"debugMode":       false,
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
