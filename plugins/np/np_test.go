package np

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

func TestStartFlow(t *testing.T) {
	pipePath := "./np"
	np, err := NewNamedPipePlugin(
		&Config{
			MaxReaders: 5,
			BuffSize:   1000,
			PipePath:   pipePath,
		},
	)
	if err != nil {
		t.Fatalf("error getting a named pipe: %v", err)
	}
	defer np.Cleanup()

	doneChan := make(chan struct{})
	flowChan := make(chan types.FlowID)
	go np.Run(doneChan, flowChan)

	tests := []struct{ in string }{
		{"start tcp 192.168.0.1 2345 127.0.0.1 5777 1 2"},
		{"start tcp         ::1 2345       ::1 5777 1 2"},
	}

	// Give the plugin a bit of time to catch up and open the pipe
	time.Sleep(1 * time.Second)

	pipe, err := os.OpenFile(pipePath, os.O_WRONLY, os.ModeNamedPipe)
	if err != nil {
		t.Fatalf("error opening the pipe: %v", err)
	}
	defer pipe.Close()

	for _, test := range tests {
		n, err := pipe.Write([]byte(test.in + "\n"))
		t.Logf("wrote %d bytes to the pipe", n)
		if err != nil {
			t.Errorf("error writing to the pipe: %v", err)
			continue
		}
		flowID := <-flowChan
		t.Logf("got a flowID: %v", flowID)
	}
}
