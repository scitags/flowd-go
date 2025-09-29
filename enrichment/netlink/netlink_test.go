//go:build linux

package netlink

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scitags/flowd-go/types"
)

func init() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource: true,
		Level:     slog.LevelError,
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

func beginListening() (net.Listener, int, error) {
	// Choose a port number automatically...
	listener, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		return nil, 0, err
	}

	addr := strings.Split(listener.Addr().String(), ":")
	port, err := strconv.Atoi(addr[len(addr)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't parse %q as a port number: %w", addr[len(addr)-1], err)
	}

	return listener, port, nil
}

func getConn(lPort int) (net.Conn, int, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", lPort))
	if err != nil {
		return nil, 0, fmt.Errorf("error dialing: %w", err)
	}

	addr := strings.Split(conn.LocalAddr().String(), ":")
	port, err := strconv.Atoi(addr[len(addr)-1])
	if err != nil {
		return nil, 0, fmt.Errorf("couldn't parse %q as a port number: %w", addr[len(addr)-1], err)
	}

	return conn, port, nil
}

func TestDumpLo(t *testing.T) {
	l, lPort, err := beginListening()
	if err != nil {
		t.Fatalf("error setting up TCP listener: %v", err)
	}
	defer l.Close()

	conn, sPort, err := getConn(lPort)
	if err != nil {
		t.Fatalf("error dialing the server: %v", err)
	}
	defer conn.Close()

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		buff := make([]byte, 1024)
		rand.Read(buff)
		for i := 0; i < 20; i++ {
			conn.Write(buff)
			time.Sleep(500 * time.Millisecond)
		}
		wg.Done()
	}()

	conf := DefaultConfig
	conf.Period = 500
	ne, err := NewEnricher(&conf)
	if err != nil {
		t.Fatalf("error getting a new enricher: %v", err)
	}
	defer ne.Cleanup()

	poller, err := ne.WatchFlow(types.FlowID{
		Src: types.IPPort{Port: uint16(sPort)},
		Dst: types.IPPort{Port: uint16(lPort)},
	})
	if err != nil {
		t.Fatalf("error getting flow information: %v", err)
	}

	wg.Add(1)
	go func() {
		<-time.Tick(15 * time.Second)
		close(poller.DoneChan)
		wg.Done()
	}()

	for r := range poller.DataChan {
		t.Logf("snapshot: %d->%d: %d, %s", r.Socket.ID.SPort, r.Socket.ID.DPort, r.TCPInfo.Bytes_sent, r.Cong.Algorithm)
	}

	t.Logf("waiting...")
	wg.Wait()
}
