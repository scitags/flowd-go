//go:build darwin || !cgo

package fireflyb

import (
	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) pollNetlinkStatus(done chan *glowdTypes.Enrichment, flowID glowdTypes.FlowID) {
}

func (b *FireflyBackend) dispatchTCPStats() {}

func (b *FireflyBackend) pollEbpfStatus(doneChan chan *glowdTypes.Enrichment, flowID glowdTypes.FlowID) {
}
