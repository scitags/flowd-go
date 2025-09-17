//go:build linux && ebpf

package skops

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/josharian/native"
	"github.com/scitags/flowd-go/types"
)

type TcpState uint8

// Check https://elixir.bootlin.com/linux/v5.14/source/include/net/tcp_states.h#L12
const (
	UNSPECIFIED TcpState = iota
	ESTABLISHED
	SYN_SENT
	SYN_RECV
	FIN_WAIT1
	FIN_WAIT2
	TIME_WAIT
	CLOSE
	CLOSE_WAIT
	LAST_ACK
	LISTEN
	CLOSING
	NEW_SYN_RECV
)

func (s TcpState) String() string {
	str, ok := map[TcpState]string{
		UNSPECIFIED:  "UNSPECIFIED",
		ESTABLISHED:  "ESTABLISHED",
		SYN_SENT:     "SYN_SENT",
		SYN_RECV:     "SYN_RECV",
		FIN_WAIT1:    "FIN_WAIT1",
		FIN_WAIT2:    "FIN_WAIT2",
		TIME_WAIT:    "TIME_WAIT",
		CLOSE:        "CLOSE",
		CLOSE_WAIT:   "CLOSE_WAIT",
		LAST_ACK:     "LAST_ACK",
		LISTEN:       "LISTEN",
		CLOSING:      "CLOSING",
		NEW_SYN_RECV: "NEW_SYN_RECV",
	}[s]
	if !ok {
		return fmt.Sprintf("UNKNOWN (%d)", s)
	}
	return str
}

type CaAlgorithm uint16

const (
	UNK CaAlgorithm = iota
	BBR
	BIC
	CDG
	RENO
	CUBIC
	DCTCP
	DCTCP_RENO
	HIGHSPEED
	HTCP
	HYBLA
	ILLINOIS
	LP
	NV
	SCALABLE
	VEGAS
	VENO
	WESTWOOD
	YEAH
)

func (a CaAlgorithm) String() string {
	str, ok := map[CaAlgorithm]string{
		UNK:        "unk",
		BBR:        "bbr",
		BIC:        "bic",
		CDG:        "cdg",
		RENO:       "reno",
		CUBIC:      "cubic",
		DCTCP:      "dctcp",
		DCTCP_RENO: "dctcp_reno",
		HIGHSPEED:  "highspeed",
		HTCP:       "htcp",
		HYBLA:      "hybla",
		ILLINOIS:   "illinois",
		LP:         "lp",
		NV:         "nv",
		SCALABLE:   "scalable",
		VEGAS:      "vegas",
		VENO:       "veno",
		WESTWOOD:   "westwood",
		YEAH:       "yeah",
	}[a]
	if !ok {
		return fmt.Sprintf("unknown (%d)", a)
	}
	return str
}

type CaState uint16

// Check https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/tcp.h#L179
const (
	OPEN CaState = iota
	DISORDER
	CWR
	RECOVERY
	LOSS
)

func (s CaState) String() string {
	str, ok := map[CaState]string{
		OPEN:     "OPEN",
		DISORDER: "DISORDER",
		CWR:      "CWR",
		RECOVERY: "RECOVERY",
		LOSS:     "LOSS",
	}[s]
	if !ok {
		return fmt.Sprintf("UNKNOWN (%d)", s)
	}
	return str
}

const TcpInfoSize = 368

// TcpInfo represents all the available data on a struct tcp_sock in the linux kernel.
// Some of the units shown in the comments accompanying members have been extracted from
// either iperf3 (https://github.com/esnet/iperf/blob/204421d895ef7b7a6546c3b8f42aae24ffa99950/src/tcp_info.c)
// or the linux kernel itself. Files of interest in the latter include net/ipv4/tcp.c, include/uapi/linux/tcp.h,
// include/linux/tcp.h, net/ipv4/tcp_diag.c and net/ipv4/inet_diag.c. Note how RFC 5681 is also a great source
// of information for the use of all these parameters.
type TcpInfo struct {
	SrcPort uint16
	DstPort uint16

	NewState               uint32
	State                  uint8
	Retransmits            uint8
	Probes                 uint8
	Backoff                uint8
	Options                uint8
	SndWscale              uint8
	RcvWscale              uint8
	DeliveryRateAppLimited uint8
	FastopenClientFail     uint32

	Rto    uint32
	Ato    uint32
	SndMss uint32 /* Sender's Maximum Segment SIze (MSS) This member is shown in iperf3 combined SndCwnd [bytes] */
	RcvMss uint32

	Unacked uint32
	Sacked  uint32
	Lost    uint32
	Retrans uint32
	Fackets uint32

	/* Times */
	LastDataSent uint32
	LastAckSent  uint32
	LastDataRecv uint32
	LastAckRecv  uint32

	/* Metrics */
	Pmtu        uint32
	RcvSsthresh uint32
	Rtt         uint32
	Rttvar      uint32
	SndSsthresh uint32 /* Slow start size threshold */
	SndCwnd     uint32 /* This member is shown in iperf3 combined with SndMss [sender's MSS]*/
	Advmss      uint32
	Reordering  uint32

	RcvRtt   uint32
	RcvSpace uint32

	TotalRetrans uint64 /* This member is shown in iperf3 [dimensionless] */

	PacingRate     uint64
	Max_pacingRate uint64
	BytesAcked     uint64 /* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	BytesReceived  uint64 /* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	SegsOut        uint32 /* RFC4898 tcpEStatsPerfSegsOut */
	SegsIn         uint32 /* RFC4898 tcpEStatsPerfSegsIn */

	NotsentBytes uint32
	MinRtt       uint32
	DataSegsIn   uint32 /* RFC4898 tcpEStatsDataSegsIn */
	DataSegsOut  uint32 /* RFC4898 tcpEStatsDataSegsOut */

	DeliveryRate uint64

	BusyTime      uint64 /* Time (usec) busy sending data */
	RwndLimited   uint64 /* Time (usec) limited by receive window */
	SndbufLimited uint64 /* Time (usec) limited by send buffer */

	Delivered   uint32
	DeliveredCe uint32

	BytesSent    uint64 /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	BytesRetrans uint64 /* RFC4898 tcpEStatsPerfOctetsRetrans */
	DsackDups    uint32 /* RFC4898 tcpEStatsStackDSACKDups */
	ReordSeen    uint32 /* reordering events seen */

	RcvOoopack uint32 /* Out-of-order packets received */

	SndWnd uint32 /* peer's advertised receive window after scaling (bytes) */

	/* TCP Congestion Algorithm (CA) Info */
	CaAlg   CaAlgorithm /* CA algorithm as a FLOW_CA_* enum member */
	CaState CaState
	CaKey   uint32
	CaFlags uint32
	Padding uint32
	CaPriv  [13]uint64
}

func (i TcpInfo) String() string {
	enc, err := json.MarshalIndent(i, "", "    ")
	if err != nil {
		return fmt.Sprintf("error marshalling TcpInfo: %v", err)
	}
	return string(enc)
}

func (i *TcpInfo) UnmarshalBinary(data []byte) error {
	b := bytes.NewReader(data)
	if b.Len() != TcpInfoSize {
		return fmt.Errorf("available data (%d) != %d", b.Len(), TcpInfoSize)
	}
	return binary.Read(b, native.Endian, i)
}

func tcpInfoToFlowInfo(ti TcpInfo) types.FlowInfo {
	return types.FlowInfo{
		Socket: &types.Socket{
			ID: types.SockID{
				SPort: ti.SrcPort,
				DPort: ti.DstPort,
			},
		},
		TCPInfo: &types.TCPInfo{
			State:                     ti.State,
			Ca_state:                  uint8(ti.CaState),
			Retransmits:               ti.Retransmits,
			Probes:                    ti.Probes,
			Backoff:                   ti.Backoff,
			Options:                   ti.Options,
			Snd_wscale:                ti.SndWscale,
			Rcv_wscale:                ti.RcvWscale,
			Delivery_rate_app_limited: ti.DeliveryRateAppLimited,
			Fastopen_client_fail:      uint8(ti.FastopenClientFail),

			Rto:     ti.Rto,
			Ato:     ti.Ato,
			Snd_mss: ti.SndMss,
			Rcv_mss: ti.RcvMss,

			Unacked: ti.Unacked,
			Sacked:  ti.Sacked,
			Lost:    ti.Lost,
			Retrans: ti.Retrans,
			Fackets: ti.Fackets,

			Last_data_sent: ti.LastDataSent,
			Last_ack_sent:  ti.LastAckSent,
			Last_data_recv: ti.LastDataRecv,
			Last_ack_recv:  ti.LastAckRecv,

			Pmtu:         ti.Pmtu,
			Rcv_ssthresh: ti.RcvSsthresh,
			Rtt:          ti.Rtt,
			Rttvar:       ti.Rttvar,
			Snd_ssthresh: ti.SndSsthresh,
			Snd_cwnd:     ti.SndCwnd,
			Advmss:       ti.Advmss,
			Reordering:   ti.Reordering,

			Rcv_rtt:   ti.RcvRtt,
			Rcv_space: ti.RcvSpace,

			Total_retrans: uint32(ti.TotalRetrans),

			Pacing_rate:     ti.PacingRate,
			Max_pacing_rate: ti.Max_pacingRate,
			Bytes_acked:     ti.BytesAcked,
			Bytes_received:  ti.BytesReceived,
			Segs_out:        ti.SegsOut,
			Segs_in:         ti.SegsIn,

			Notsent_bytes: ti.NotsentBytes,
			Min_rtt:       ti.MinRtt,
			Data_segs_in:  ti.DataSegsIn,
			Data_segs_out: ti.DataSegsOut,

			Delivery_rate: ti.DeliveryRate,

			Busy_time:      ti.BusyTime,
			Rwnd_limited:   ti.RwndLimited,
			Sndbuf_limited: ti.SndbufLimited,

			Delivered:    ti.Delivered,
			Delivered_ce: ti.DeliveredCe,

			Bytes_sent:    ti.BytesSent,
			Bytes_retrans: ti.BytesRetrans,
			Dsack_dups:    ti.DsackDups,
			Reord_seen:    ti.ReordSeen,

			Rcv_ooopack: ti.RcvOoopack,
			Snd_wnd:     ti.SndWnd,
		},
		Cong: &types.Cong{
			Algorithm: ti.CaAlg.String(),
		},
	}
}
