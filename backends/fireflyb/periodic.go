package fireflyb

import (
	"log/slog"

	"github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) periodicFFs(f types.FlowID, flavour types.Flavour, fic chan *types.FlowInfo) {
	slog.Debug("starting periodic firefly goroutine", "flowID", f, "flavour", flavour)
	ff := types.Firefly{}
	f.State = types.ONGOING

	for fi := range fic {
		fi.Mode = b.EnrichmentMode

		switch flavour {
		case types.Ebpf:
			ff = types.NewFirefly(f, nil, fi, nil)
		case types.Netlink:
			ff = types.NewFirefly(f, fi, nil, nil)
		}

		payload, err := ff.Payload(b.PrependSyslog)
		if err != nil {
			slog.Error("error building periodic firefly", "err", err)
			continue
		}

		if err := b.sendFirefly(f, payload); err != nil {
			slog.Error("error sending periodic firefly", "err", err)
		}
	}

	slog.Debug("exiting periodic firefly goroutine", "flowID", f)
}

func (b *FireflyBackend) endEvent(fic chan *types.FlowInfo, uc chan types.FlowUsage) {
	for fi := range fic {
		slog.Debug("got tcp event on endEvent", "state", types.State(fi.NewState))

		// Wait for fic closure for cleanup!
		if types.State(fi.NewState) == types.TCP_CLOSE {
			uc <- types.FlowUsage{Sent: fi.TCPInfo.Bytes_sent, Received: fi.TCPInfo.Bytes_received}
		}
	}
}
