//go:build linux && cgo

package skops

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
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

func TestEbpfAttach(t *testing.T) {
	if err := Init(); err != nil {
		t.Errorf("error attaching the program: %v\n", err)
	}
}
