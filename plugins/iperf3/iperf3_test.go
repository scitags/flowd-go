package iperf3

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scitags/flowd-go/types"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelDebug,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			// Remove time.
			if a.Key == slog.TimeKey && len(groups) == 0 {
				return slog.Attr{}
			}
			// Remove the directory from the source's filename.
			if a.Key == slog.SourceKey {
				source := a.Value.Any().(*slog.Source)
				source.File = filepath.Base(source.File)
			}
			return a
		},
	}))
	slog.SetDefault(logger)
}

func TestIntegration(t *testing.T) {
	p, err := NewIperf3Plugin(&Config{
		MinSourcePort: 2340,
		MaxSourcePort: 2350,

		MinDestinationPort: 5200,
		MaxDestinationPort: 5210,

		ActivityIDs:   []int{0, 1, 2},
		ExperimentIDs: []int{0, 1, 2},

		DebugMode: true,
	})
	if err != nil {
		t.Fatalf("error creating the plugin: %v", err)
	}
	defer p.Cleanup()

	done := make(chan struct{})
	fChan := make(chan types.FlowID)
	go func() {
		t.Logf("waiting to close the done channel")
		<-time.Tick(20 * time.Second)
		t.Logf("closing the done channel")
		close(done)
	}()

	go p.Run(done, fChan)

	for f := range fChan {
		t.Logf("got flowID: %v", f)
	}
}
