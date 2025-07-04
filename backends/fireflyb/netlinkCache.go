package fireflyb

import (
	"log/slog"
	"sync"
	"time"

	glowdTypes "github.com/scitags/flowd-go/types"
)

type cacheEntry struct {
	doneChan chan *glowdTypes.Enrichment
	startTs  time.Time
	wg       sync.WaitGroup
}

type connectionCache struct {
	sync.Mutex
	cache map[uint64]*cacheEntry
}

func NewConnectionCache(cap int) *connectionCache {
	return &connectionCache{cache: make(map[uint64]*cacheEntry, cap)}
}

func (cc *connectionCache) Get(key uint64) (*cacheEntry, bool) {
	cc.Lock()
	entry, ok := cc.cache[key]
	cc.Unlock()
	return entry, ok
}

func (cc *connectionCache) Insert(key uint64, startTs time.Time) (*cacheEntry, bool) {
	entry := &cacheEntry{doneChan: make(chan *glowdTypes.Enrichment), startTs: startTs, wg: sync.WaitGroup{}}

	cc.Lock()
	_, ok := cc.cache[key]
	if !ok {
		cc.cache[key] = entry
	}
	cc.Unlock()

	return entry, ok
}

func (cc *connectionCache) CloseChan(key uint64) {
	cc.Lock()
	close(cc.cache[key].doneChan)
	cc.Unlock()
}

func (cc *connectionCache) Remove(key uint64) {
	cc.Lock()
	delete(cc.cache, key)
	cc.Unlock()
}

func (b *FireflyBackend) hashFlowID(flowID glowdTypes.FlowID) uint64 {
	// Encoding a flowID will never fail!
	enc, _ := flowID.MarshalBinary()

	b.hashGen.Reset()
	b.hashGen.Write(enc)

	hash := b.hashGen.Sum64()

	slog.Debug("hashed flowID", "hash", hash)

	return hash
}
