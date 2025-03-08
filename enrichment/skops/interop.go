package skops

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type TcpState uint8

// Check https://elixir.bootlin.com/linux/v5.14/source/include/net/tcp_states.h#L12
const (
	ESTABLISHED TcpState = iota + 1
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
		UNK:        "UNK",
		BBR:        "BBR",
		BIC:        "BIC",
		CDG:        "CDG",
		RENO:       "RENO",
		CUBIC:      "CUBIC",
		DCTCP:      "DCTCP",
		DCTCP_RENO: "DCTCP_RENO",
		HIGHSPEED:  "HIGHSPEED",
		HTCP:       "HTCP",
		HYBLA:      "HYBLA",
		ILLINOIS:   "ILLINOIS",
		LP:         "LP",
		NV:         "NV",
		SCALABLE:   "SCALABLE",
		VEGAS:      "VEGAS",
		VENO:       "VENO",
		WESTWOOD:   "WESTWOOD",
		YEAH:       "YEAH",
	}[a]
	if !ok {
		return fmt.Sprintf("UNKNOWN (%d)", a)
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

const TcpInfoSize = 360

type TcpInfo struct {
	State                  TcpState
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
	SndMss uint32
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
	SndSsthresh uint32
	SndCwnd     uint32
	Advmss      uint32
	Reordering  uint32

	RcvRtt   uint32
	RcvSpace uint32

	TotalRetrans uint64

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

	Bytes_sent    uint64 /* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	Bytes_retrans uint64 /* RFC4898 tcpEStatsPerfOctetsRetrans */
	DsackDups     uint32 /* RFC4898 tcpEStatsStackDSACKDups */
	ReordSeen     uint32 /* reordering events seen */

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

// func (i TcpInfo) MarshalBinary() ([]byte, error) {
// 	enc := append([]byte{}, f.Src.IP...)
// 	enc = append(enc, f.Dst.IP...)
// 	binary.LittleEndian.AppendUint16(enc, f.Src.Port)
// 	binary.LittleEndian.AppendUint16(enc, f.Dst.Port)
// 	return enc, nil
// }

func checkDeserErr(err error) error {
	if err == io.EOF {
		return nil
	}
	return err
}

func (i *TcpInfo) UnmarshalBinary(data []byte) error {
	buff := bytes.NewBuffer(data)
	if buff.Len() != TcpInfoSize {
		return fmt.Errorf("available data (%d) != %d", buff.Available(), TcpInfoSize)
	}

	stateRaw, err := buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.State = TcpState(stateRaw)

	i.Retransmits, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.Probes, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.Backoff, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.Options, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.SndWscale, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.RcvWscale, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	i.DeliveryRateAppLimited, err = buff.ReadByte()
	if err != nil {
		return checkDeserErr(err)
	}
	next := buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.FastopenClientFail = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Rto = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Ato = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SndMss = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.RcvMss = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Unacked = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Sacked = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Lost = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Retrans = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Fackets = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.LastDataSent = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.LastAckSent = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.LastDataRecv = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.LastAckRecv = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Pmtu = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.RcvSsthresh = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Rtt = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Rttvar = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SndSsthresh = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SndCwnd = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Advmss = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Reordering = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.RcvRtt = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.RcvSpace = binary.NativeEndian.Uint32(next)

	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.TotalRetrans = binary.NativeEndian.Uint64(next)
	// fmt.Printf("offset @ PacingRate: %d\n", TcpInfoSize-buff.Len())

	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.PacingRate = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.Max_pacingRate = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.BytesAcked = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.BytesReceived = binary.NativeEndian.Uint64(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SegsOut = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SegsIn = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.NotsentBytes = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.MinRtt = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.DataSegsIn = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.DataSegsOut = binary.NativeEndian.Uint32(next)

	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.DeliveryRate = binary.NativeEndian.Uint64(next)

	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.BusyTime = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.RwndLimited = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.SndbufLimited = binary.NativeEndian.Uint64(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.Delivered = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.DeliveredCe = binary.NativeEndian.Uint32(next)

	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.Bytes_sent = binary.NativeEndian.Uint64(next)
	next = buff.Next(8)
	if len(next) == 0 {
		return nil
	}
	i.Bytes_retrans = binary.NativeEndian.Uint64(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.DsackDups = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.ReordSeen = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.RcvOoopack = binary.NativeEndian.Uint32(next)

	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.SndWnd = binary.NativeEndian.Uint32(next)

	fmt.Printf("offset: %d\n", TcpInfoSize-buff.Len())
	next = buff.Next(2)
	if len(next) == 0 {
		return nil
	}
	i.CaAlg = CaAlgorithm(binary.NativeEndian.Uint16(next))
	fmt.Printf("offset: %d\n", TcpInfoSize-buff.Len())
	next = buff.Next(2)
	if len(next) == 0 {
		return nil
	}
	i.CaState = CaState(binary.NativeEndian.Uint16(next))
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.CaKey = binary.NativeEndian.Uint32(next)
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	next = buff.Next(4)
	if len(next) == 0 {
		return nil
	}
	i.CaFlags = binary.NativeEndian.Uint32(next)
	for j := 0; j < 13; j++ {
		next = buff.Next(8)
		if len(next) == 0 {
			return nil
		}
		i.CaPriv[j] = binary.NativeEndian.Uint64(next)
	}

	return nil
}
