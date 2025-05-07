package fireflyb

import (
	"log/slog"
	"sync"

	"github.com/scitags/flowd-go/enrichment/netlink"
	glowdTypes "github.com/scitags/flowd-go/types"
)

type connectionCache struct {
	sync.Mutex
	cache map[uint64]chan *netlink.InetDiagTCPInfoResp
}

func NewConnectionCache(cap int) *connectionCache {
	return &connectionCache{cache: make(map[uint64]chan *netlink.InetDiagTCPInfoResp, cap)}
}

func (cc *connectionCache) Get(key uint64) (chan *netlink.InetDiagTCPInfoResp, bool) {
	cc.Lock()
	doneChan, ok := cc.cache[key]
	cc.Unlock()
	return doneChan, ok
}

func (cc *connectionCache) Insert(key uint64) (chan *netlink.InetDiagTCPInfoResp, bool) {
	doneChan := make(chan *netlink.InetDiagTCPInfoResp)

	cc.Lock()
	_, ok := cc.cache[key]
	if !ok {
		cc.cache[key] = doneChan
	}
	cc.Unlock()

	return doneChan, ok
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
