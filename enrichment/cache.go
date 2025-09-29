package enrichment

import (
	"hash/fnv"
	"sync"
	"time"

	"github.com/scitags/flowd-go/types"
)

type Poller struct {
	DoneChan chan struct{}
	DataChan chan *types.FlowInfo
	StartTS  time.Time
}

// We could consider using sync.Map, but it doesn't really fit
// our use case...
type FlowCache struct {
	sync.Mutex
	cache map[uint64]Poller
}

func NewFlowCache(cap int) *FlowCache {
	return &FlowCache{cache: make(map[uint64]Poller, cap)}
}

func (fc *FlowCache) Get(key uint64) (Poller, bool) {
	fc.Lock()
	cache, ok := fc.cache[key]
	fc.Unlock()
	return cache, ok
}

func (fc *FlowCache) GetLock(key uint64) (Poller, *sync.Mutex, bool) {
	fc.Lock()
	cache, ok := fc.cache[key]
	return cache, &fc.Mutex, ok
}

func (fc *FlowCache) Insert(key uint64, ts time.Time) (Poller, bool) {
	poller := Poller{
		DoneChan: make(chan struct{}),
		DataChan: make(chan *types.FlowInfo),
		StartTS:  ts,
	}

	fc.Lock()
	_, ok := fc.cache[key]
	if !ok {
		fc.cache[key] = poller
	}
	fc.Unlock()

	return poller, ok
}

func (fc *FlowCache) MarkForRemoval(key uint64) (time.Time, bool) {
	var ts time.Time
	fc.Lock()
	poller, ok := fc.cache[key]
	if ok {
		ts = poller.StartTS
		close(poller.DoneChan)
	}
	fc.Unlock()
	return ts, ok
}

func (fc *FlowCache) Remove(key uint64) {
	fc.Lock()
	close(fc.cache[key].DataChan)
	delete(fc.cache, key)
	fc.Unlock()
}

func HashFlowID(flowID types.FlowID) uint64 {
	// Encoding a flowID will never fail!
	enc, _ := flowID.MarshalBinary()

	h := fnv.New64a()
	h.Write(enc)
	hash := h.Sum64()

	return hash
}
