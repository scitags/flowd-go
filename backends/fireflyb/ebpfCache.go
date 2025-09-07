package fireflyb

import (
	"sync"

	glowdTypes "github.com/scitags/flowd-go/types"
)

type ebpfPoller struct {
	doneChan chan struct{}
	dataChan chan *glowdTypes.Enrichment
}

type ebpfConnectionCache struct {
	sync.Mutex
	cache map[uint64]ebpfPoller
}

func NewEbpfConnectionCache(cap int) *ebpfConnectionCache {
	return &ebpfConnectionCache{cache: make(map[uint64]ebpfPoller, cap)}
}

func (cc *ebpfConnectionCache) Get(key uint64) (ebpfPoller, bool) {
	cc.Lock()
	cache, ok := cc.cache[key]
	cc.Unlock()
	return cache, ok
}

func (cc *ebpfConnectionCache) Insert(key uint64) (ebpfPoller, bool) {
	poller := ebpfPoller{
		doneChan: make(chan struct{}),
		dataChan: make(chan *glowdTypes.Enrichment),
	}

	cc.Lock()
	_, ok := cc.cache[key]
	if !ok {
		cc.cache[key] = poller
	}
	cc.Unlock()

	return poller, ok
}

func (cc *ebpfConnectionCache) MarkForRemoval(key uint64) {
	cc.Lock()
	poller, ok := cc.cache[key]
	if ok {
		close(poller.doneChan)
	}
	cc.Unlock()
}

func (cc *ebpfConnectionCache) Remove(key uint64) {
	cc.Lock()
	close(cc.cache[key].dataChan)
	delete(cc.cache, key)
	cc.Unlock()
}
