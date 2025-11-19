package xrootd

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

func TestRecv(t *testing.T) {
	p, err := NewXrootdProcessor(&Config{
		BindAddress: "127.0.0.1",
		BindPort:    8888,
		BufferSize:  2048,
		Deadline:    0,
	})
	if err != nil {
		t.Fatalf("error creating processor: %v", err)
	}
	defer p.Cleanup()

	doneChan := make(chan struct{})
	p.Run(doneChan)
}
