package fireflyb

import (
	"log/slog"
	"time"

	"github.com/scitags/flowd-go/types"
)

func (b *FireflyBackend) PeriodicFFs(flowID types.FlowID) {
	for k, v := range b.enrichers {
		poller, err := v.WatchFlow(flowID)
		if err != nil {
			slog.Warn("couldn't get a poller", "flavour", k, "err", err)
			continue
		}

		go func() {
			slog.Debug("starting periodic firefly goroutine", "flowID", flowID, "flavour", k)
			ff := types.Firefly{}
			flowID.State = types.ONGOING

			for fi := range poller.DataChan {
				fi.Verbosity = b.EnrichmentVerbosity

				switch k {
				case types.Ebpf:
					ff = types.NewFirefly(flowID, nil, fi)
				case types.Netlink:
					ff = types.NewFirefly(flowID, fi, nil)
				default:
					slog.Warn("wrong enrichment flavour", "flavour", k)
				}

				payload, err := ff.Payload(b.PrependSyslog)
				if err != nil {
					slog.Error("error building periodic firefly", "err", err)
					continue
				}

				if err := b.sendFirefly(flowID, payload); err != nil {
					slog.Error("error sending periodic firefly", "err", err)
				}
			}

			slog.Debug("exiting periodic firefly goroutine", "flowID", flowID)
		}()
	}
}

func (b *FireflyBackend) RemoveFlow(flowID types.FlowID) time.Time {
	var sts time.Time
	slog.Debug("removing flow", "flowID", flowID)
	for _, v := range b.enrichers {
		ts, ok := v.ForgetFlow(flowID)
		if !ok {
			slog.Warn("tried to forget a non-existent flow", "flowID", flowID)
		}
		// Both timestamps should be the same... room for improvement!
		sts = ts
	}
	return sts
}
