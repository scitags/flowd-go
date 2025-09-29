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
		fi.Verbosity = b.EnrichmentVerbosity

		switch flavour {
		case types.Ebpf:
			ff = types.NewFirefly(f, nil, fi)
		case types.Netlink:
			ff = types.NewFirefly(f, fi, nil)
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
