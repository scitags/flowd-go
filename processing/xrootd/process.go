package xrootd

import (
	"fmt"
	"log/slog"
	"net"

	"github.com/jellydator/ttlcache/v3"
)

type TransferCacheValue struct {
	TBeg uint32
	Addr net.IP
	Msg  MonFileOPN
}

// Reimplementation of [0].
//
// 0: https://github.com/opensciencegrid/xrootd-monitoring-collector
func (p *XrootdProcessor) Process(msg *MonMessage, addr *net.UDPAddr) error {
	// Compute a unique server Id
	serverId := fmt.Sprintf("%d#%s#%d", msg.Hdr.Stod, addr.IP, addr.Port)

	slog.Debug("processing message", "serverId", serverId)

	seqCachePtr, ok := p.sequenceCache.GetOrSet(serverId, map[byte]byte{})
	if !ok {
		slog.Debug("populated sequence cache", "serverId", serverId)
	}
	seqCache := seqCachePtr.Value()

	seq, ok := seqCache[msg.Hdr.Code]
	if !ok {
		seq = msg.Hdr.Pseq
	}
	seqCache[msg.Hdr.Code] = byte(uint16(seq+1) % 256)

	// Be smarter about this...
	if seq != msg.Hdr.Pseq {
		slog.Error("got un unexpected sequence number", "code", msg.Hdr.Code, "seq", seq)
	}
	p.sequenceCache.Set(serverId, seqCache, ttlcache.DefaultTTL)

	switch msg.Hdr.Code {
	case 'f':
		if msg.Fstream.Opn != nil {
			transferKey := fmt.Sprintf("%s.%d", serverId, msg.Fstream.Opn.Hdr.IdRecs)

			slog.Debug("processing MonOpn", "transferKey", transferKey)

			p.transferCache.Set(transferKey, TransferCacheValue{
				TBeg: msg.Fstream.Tod.TBeg,
				Addr: addr.IP,
				Msg:  *msg.Fstream.Opn,
			}, ttlcache.DefaultTTL)
		}

		if msg.Fstream.Cls != nil {
			transferKey := fmt.Sprintf("%s.%d", serverId, msg.Fstream.Opn.Hdr.IdRecs)

			slog.Debug("processing MonCls", "transferKey", transferKey)

			e, ok := p.transferCache.GetAndDelete(transferKey)
			if ok {
				v := e.Value()
				p.AddRecord("isClose", v.Addr, v.Msg.Ufn.Lfn)
			} else {
				slog.Error("closing nonexistent entry", "transferKey", transferKey)
			}
		}
	default:
		slog.Warn("unimplemented code", "code", msg.Hdr.Code)
	}

	// Send information over AMQP...

	return nil
}

func (p *XrootdProcessor) AddRecord(args ...interface{}) {
	slog.Debug("adding record...", "args", fmt.Sprintf("%v", args))
}
