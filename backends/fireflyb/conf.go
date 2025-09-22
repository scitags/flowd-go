package fireflyb

import (
	"github.com/scitags/flowd-go/enrichment/skops"
)

var (
	Defaults = map[string]interface{}{
		"fireflyDestinationPort": 10514,
		"prependSyslog":          true,

		"sendToCollector":  false,
		"collectorAddress": "127.0.0.1",
		"collectorPort":    10514,

		"periodicFireflies":   false,
		"period":              1000,
		"enrichmentVerbosity": "lean",

		"addNetlinkContext": true,

		"skOpsAddBPFContext": false,
		"skOpsCgroupPath":    "/",
		"skOpsProgramPath":   "",
		"skOpsStrategy":      skops.Poll,
		"skOpsDebugMode":     false,
	}
)
