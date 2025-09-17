//go:buid linux && ebpf

package skops

import (
	"sync"
	"testing"
	"time"

	"github.com/scitags/flowd-go/types"
)

func TestParsing(t *testing.T) {
	rawsample := []byte{41, 9, 145, 22, 0, 0, 0, 0, 1, 0, 0, 0, 7, 7, 7, 0, 0, 0, 0, 0, 248, 24, 3, 0, 0, 0, 0, 0, 148, 5, 0, 0, 24, 2, 220, 5, 168, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 5, 0, 0, 0, 0, 0, 0, 220, 5, 0, 0, 108, 124, 0, 0, 170, 8, 0, 0, 182, 0, 0, 0, 72, 0, 0, 0, 18, 1, 0, 0, 148, 5, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 200, 55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 30, 158, 12, 0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 255, 255, 158, 231, 202, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 50, 148, 1, 0, 101, 28, 0, 0, 88, 146, 21, 0, 123, 0, 0, 0, 0, 0, 0, 0, 48, 148, 1, 0, 188, 24, 138, 6, 0, 0, 0, 0, 216, 100, 19, 0, 208, 7, 0, 0, 232, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 137, 147, 1, 0, 0, 0, 0, 0, 189, 144, 206, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 115, 9, 0, 5, 0, 0, 0, 240, 48, 155, 187, 1, 0, 0, 0, 0, 0, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 17, 1, 0, 0, 62, 3, 236, 137, 72, 0, 0, 0, 0, 0, 0, 0, 123, 0, 0, 0, 136, 254, 235, 137, 102, 1, 0, 0, 85, 0, 0, 0, 0, 0, 4, 1, 165, 187, 189, 211, 100, 211, 226, 225, 255, 188, 189, 211, 164, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

	tcpInfo := TcpInfo{}
	if err := tcpInfo.UnmarshalBinary(rawsample); err != nil {
		t.Fatalf("error unmarshaling raw sample: %v", err)
	}

	t.Logf("tcpInfo: %+v", tcpInfo)

	// newTcpInfo := TcpInfo{}
	// if err := newTcpInfo.Unmarshall(rawsample); err != nil {
	// 	t.Fatalf("error unmarshaling raw sample: %v", err)
	// }

	// t.Logf("tcpInfo: %+v", newTcpInfo)

	// if !cmp.Equal(tcpInfo, newTcpInfo) {
	// 	t.Errorf("tcpInfo != newTcpInfo")
	// }
}

func TestInterop(t *testing.T) {
	enricher, err := NewEnricher(100 * NS_PER_MS)
	if err != nil {
		t.Fatalf("error creating the enricher: %v", err)
	}
	defer enricher.Cleanup()

	doneChan := make(chan struct{})
	go enricher.Run(doneChan)

	time.Sleep(1 * time.Second)

	poller, err := enricher.WatchFlow(types.FlowID{
		Src: types.IPPort{Port: 2345},
		Dst: types.IPPort{Port: 5777},
	})
	if err != nil {
		t.Fatalf("error starting the poller: %v", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	go func() {
		time.Sleep(20 * time.Second)
		close(poller.DoneChan)
		time.Sleep(1 * time.Second)
		close(doneChan)
		wg.Done()
	}()

	for r := range poller.DataChan {
		t.Logf("snapshot: %+v", r)
	}

	t.Logf("waiting...")
	wg.Wait()
}
