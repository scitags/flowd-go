package stun

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

func TestGetDefaultInterface(t *testing.T) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Errorf("error getting the default interface: %v", err)
	}
	t.Logf("default interface; name: %s, index: %d", i.Name, i.Index)
}

func TestGetInterfaceAddresses(t *testing.T) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Errorf("error getting the default interface: %v", err)
	}
	t.Logf("default interface; name: %s, index: %d", i.Name, i.Index)

	ip4, ip6, err := GetInterfaceAddresses(i)
	if err != nil {
		t.Errorf("error getting the interface addresses: %v", err)
	}
	t.Logf("interface addresses; ip4: %+v, ip6: %+v", ip4, ip6)
}

func TestGetPublicAddresses(t *testing.T) {
	pubIPs, err := GetPublicAddresses()
	if err != nil {
		t.Errorf("error getting the public IPs: %v", err)
	}
	t.Logf("pubIPs: %+v", pubIPs)
}
