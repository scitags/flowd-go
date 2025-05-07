//go:build darwin || !cgo

package fireflyb

import (
	"log/slog"

	"github.com/scitags/flowd-go/enrichment/netlink"
	glowdTypes "github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) pollNetlinkStatus(done chan *netlink.InetDiagTCPInfoResp, flowID glowdTypes.FlowID) {
	slog.Debug("entering netlink polling goroutine", "flowID", flowID)
	for {
		select {
		case <-done:
			slog.Debug("quitting netlink polling goroutine", "flowID", flowID)
			done <- nil
			return
		}
	}
}
