package fireflyb

import (
	"sync"

	glowdTypes "github.com/scitags/flowd-go/types"
)

type ebpfConnectionCache struct {
	sync.Mutex
	cache map[uint64][]*glowdTypes.Enrichment
}

func NewEbpfConnectionCache(cap int) *ebpfConnectionCache {
	return &ebpfConnectionCache{cache: make(map[uint64][]*glowdTypes.Enrichment, cap)}
}

func (cc *ebpfConnectionCache) Get(key uint64) ([]*glowdTypes.Enrichment, bool) {
	cc.Lock()
	cache, ok := cc.cache[key]
	cc.Unlock()
	return cache, ok
}

func (cc *ebpfConnectionCache) Create(key uint64) bool {
	cc.Lock()
	_, ok := cc.cache[key]
	if !ok {
		cc.cache[key] = make([]*glowdTypes.Enrichment, 0, 10)
	}
	cc.Unlock()

	return ok
}

func (cc *ebpfConnectionCache) Insert(key uint64, val *glowdTypes.Enrichment) {
	cc.Lock()
	cc.cache[key] = append(cc.cache[key], val)
	cc.Unlock()
}

func (cc *ebpfConnectionCache) Remove(key uint64) {
	cc.Lock()
	delete(cc.cache, key)
	cc.Unlock()
}
