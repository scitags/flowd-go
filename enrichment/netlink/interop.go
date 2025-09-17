//go:build linux

package netlink

import (
	"github.com/scitags/flowd-go/types"
	"github.com/scitags/go-diag"
)

func inetDiagToFlowInfo(no diag.NetObject) types.FlowInfo {
	fi := types.FlowInfo{
		Socket: &types.Socket{
			Family:  no.Family,
			State:   no.State,
			Timer:   no.Timer,
			Retrans: no.Retrans,
			ID: types.SockID{
				SPort:  no.ID.SPort,
				DPort:  no.ID.DPort,
				Src:    no.ID.Src,
				Dst:    no.ID.Dst,
				If:     no.ID.If,
				Cookie: no.ID.Cookie,
			},
			Expires: no.Expires,
			RQueue:  no.RQueue,
			WQueue:  no.WQueue,
			UID:     no.UID,
			INode:   no.INode,
		},
	}

	if no.TcpInfo != nil {
		fi.TCPInfo = &types.TCPInfo{
			State:                     no.TcpInfo.State,
			Ca_state:                  no.TcpInfo.CaState,
			Retransmits:               no.TcpInfo.Retransmits,
			Probes:                    no.TcpInfo.Probes,
			Backoff:                   no.TcpInfo.Backoff,
			Options:                   no.TcpInfo.Options,
			Snd_wscale:                (no.TcpInfo.Wscale & 0xF0) >> 4,
			Rcv_wscale:                no.TcpInfo.Wscale & 0x0F,
			Delivery_rate_app_limited: no.TcpInfo.ClientInfo & 0x1,
			Fastopen_client_fail:      (no.TcpInfo.ClientInfo & 0x2) >> 1,

			Rto:     no.TcpInfo.Rto,
			Ato:     no.TcpInfo.Ato,
			Snd_mss: no.TcpInfo.SndMss,
			Rcv_mss: no.TcpInfo.RcvMss,

			Unacked: no.TcpInfo.Unacked,
			Sacked:  no.TcpInfo.Sacked,
			Lost:    no.TcpInfo.Lost,
			Retrans: no.TcpInfo.Retrans,
			Fackets: no.TcpInfo.Fackets,

			Last_data_sent: no.TcpInfo.LastDataSent,
			Last_ack_sent:  no.TcpInfo.LastAckSent,
			Last_data_recv: no.TcpInfo.LastDataRecv,
			Last_ack_recv:  no.TcpInfo.LastAckRecv,

			Pmtu:         no.TcpInfo.Pmtu,
			Rcv_ssthresh: no.TcpInfo.RcvSsthresh,
			Rtt:          no.TcpInfo.Rtt,
			Rttvar:       no.TcpInfo.Rttvar,
			Snd_ssthresh: no.TcpInfo.SndSsthresh,
			Snd_cwnd:     no.TcpInfo.SndCwnd,
			Advmss:       no.TcpInfo.Advmss,
			Reordering:   no.TcpInfo.Reordering,

			Rcv_rtt:   no.TcpInfo.RcvRtt,
			Rcv_space: no.TcpInfo.RcvSpace,

			Total_retrans: no.TcpInfo.RotalRetrans,

			Pacing_rate:     no.TcpInfo.PacingRate,
			Max_pacing_rate: no.TcpInfo.MaxPacingRate,
			Bytes_acked:     no.TcpInfo.BytesAcked,
			Bytes_received:  no.TcpInfo.BytesReceived,
			Segs_out:        no.TcpInfo.SegsOut,
			Segs_in:         no.TcpInfo.SegsIn,

			Notsent_bytes: no.TcpInfo.NotsentBytes,
			Min_rtt:       no.TcpInfo.MinRtt,
			Data_segs_in:  no.TcpInfo.DataSegsIn,
			Data_segs_out: no.TcpInfo.DataSegsOut,

			Delivery_rate: no.TcpInfo.DeliveryRate,

			Busy_time:      no.TcpInfo.BusyTime,
			Rwnd_limited:   no.TcpInfo.RwndLimited,
			Sndbuf_limited: no.TcpInfo.SndbufLimited,

			Delivered:    no.TcpInfo.Delivered,
			Delivered_ce: no.TcpInfo.DeliveredCe,

			Bytes_sent:    no.TcpInfo.BytesSent,
			Bytes_retrans: no.TcpInfo.BytesRetrans,
			Dsack_dups:    no.TcpInfo.DsackDups,
			Reord_seen:    no.TcpInfo.ReordSeen,

			Rcv_ooopack: no.TcpInfo.RcvOoopack,
			Snd_wnd:     no.TcpInfo.SndWnd,
		}
	}

	if no.Cong != nil {
		fi.Cong = &types.Cong{
			Algorithm: *no.Cong,
		}
	}

	if no.BBRInfo != nil {
		fi.BBRInfo = &types.TCPBBRInfo{
			BBRBW:         uint64(no.BBRInfo.BwHi)<<32 | uint64(no.BBRInfo.BwLo),
			BBRMinRTT:     no.BBRInfo.MinRTT,
			BBRPacingGain: no.BBRInfo.PacingGain,
			BBRCwndGain:   no.BBRInfo.CwndGaing,
		}
	}

	if no.TOS != nil {
		fi.TOS = &types.TOS{
			TOS: *no.TOS,
		}
	}

	if no.MemInfo != nil {
		fi.MemInfo = &types.MemInfo{
			RMem: no.MemInfo.RMem,
			WMem: no.MemInfo.WMem,
			FMem: no.MemInfo.FMem,
			TMem: no.MemInfo.TMem,
		}
	}

	if no.SkMemInfo != nil {
		fi.SkMemInfo = &types.SkMemInfo{
			RMemAlloc:  no.SkMemInfo.RMemAlloc,
			RcvBuff:    no.SkMemInfo.RcvBuff,
			WMemAlloc:  no.SkMemInfo.WMemAlloc,
			SndBuff:    no.SkMemInfo.SndBuff,
			FwdAlloc:   no.SkMemInfo.FwdAlloc,
			WMemQueued: no.SkMemInfo.WMemQueued,
			OptMem:     no.SkMemInfo.OptMem,
			Backlog:    no.SkMemInfo.Backlog,
			Drops:      no.SkMemInfo.Drops,
		}
	}

	if no.VegasInfo != nil {
		fi.VegasInfo = &types.VegasInfo{
			Enabled:  no.VegasInfo.Enabled,
			RTTCount: no.VegasInfo.RttCnt,
			RTT:      no.VegasInfo.Rtt,
			MinRTT:   no.VegasInfo.MinRtt,
		}
	}

	if no.DCTCPInfo != nil {
		fi.DCTCPInfo = &types.DCTCPInfo{
			Enabled: no.DCTCPInfo.Enabeld,
			CEState: no.DCTCPInfo.CeState,
			Alpha:   no.DCTCPInfo.Alpha,
			ABEcn:   no.DCTCPInfo.AbECN,
			ABTot:   no.DCTCPInfo.AbTot,
		}
	}

	return fi
}
