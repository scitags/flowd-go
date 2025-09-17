package types

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/structs"
)

// validTags encodes valid struct tags allowing for
// the control of marshalling of Enrichment structs.
var validTags = map[string]struct{}{
	// When leveraging the lean tag a large portion of the Enrichment struct
	// WILL NOT be marshaled. This is explained by how the several fields
	// have an associated `lean:"-"` tag.
	"lean": {},

	// When leveraging the compatible tag, an Enrichment struct will be marshalled
	// into a flowd-compatible struct that's largely an 'unwrapped' version of
	// the enrichment struct.
	"compatible": {},
}

// Flavour encodes the enrichment source (i.e. eBPF or netlink).
type Flavour uint8

const (
	// An eBPF (i.e. sock_ops) enricher
	Ebpf Flavour = iota

	// A netlink enricher
	Netlink
)

// Enrichment encodes all the connection enrichment information for a
// particular flow. The addition of several struct tags allows for a precise
// control over what fields are marshalled.
type FlowInfo struct {
	Verbosity string      `structs:"-" lean:"-"`
	TCPInfo   *TCPInfo    `structs:"tcpInfo" lean:"tcpInfo"`
	Cong      *Cong       `structs:"cong,omitempty" lean:"cong,omitempty"`
	Socket    *Socket     `structs:"skBuff,omitempty" lean:"-"`
	BBRInfo   *TCPBBRInfo `structs:"bbr,omitempty" lean:"-"`
	TOS       *TOS        `structs:"tos,omitempty" lean:"-"`
	MemInfo   *MemInfo    `structs:"memInfo,omitempty" lean:"-"`
	SkMemInfo *SkMemInfo  `structs:"skMemInfo,omitempty" lean:"-"`
	VegasInfo *VegasInfo  `structs:"vegasInfo,omitempty" lean:"-"`
	DCTCPInfo *DCTCPInfo  `structs:"dctcpInfo,omitempty" lean:"-"`
}

// MarshalJSON implements the json.Marshaler interface. We'll simply leverage
// structs to play around with the struct tags in an effort to control the
// marshalling output. The idea here is that we can choose what struct tag to
// use when marshalling. The default tag is `structs`. We can however choose
// among any other available tags to decide what fields make it into the end
// result. For example, `lean` will only output a small subset of fields so
// as not to overflow the maximum firefly size of a single MTU (~ 1500 bytes).
// Valid tags are contained in the validTags map. The definition of the
// validTags map contains embedded comments explaining what the purpose of each
// tag is.
func (e *FlowInfo) MarshalJSON() ([]byte, error) {
	s := structs.New(e)

	if e.Verbosity != "" {
		_, ok := validTags[e.Verbosity]
		if ok {
			if e.Verbosity == "compatible" {
				return json.Marshal(NewCompatibilityEnrichment(e))
			} else {
				s.TagName = e.Verbosity
			}
		}
	}

	return json.Marshal(s.Map())
}

// SockID mirrors diag.SockID so as to add struct tags for marshalling.
// It contains information specifying the source and destination addresses
// along some other identifiable information.
type SockID struct {
	// Source port in network byte order (i.e. use Ntohs())
	SPort uint16 `structs:"srcPort" lean:"-"`

	// Destination port in network byte order (i.e. use Ntohs())
	DPort uint16 `structs:"dstPort" lean:"-"`

	// Source IPv{4,6} address
	Src [4]uint32 `structs:"srcIP" lean:"-"`

	// Destination IPv{4,6} address
	Dst [4]uint32 `structs:"dstIP" lean:"-"`

	// Interface identifier
	If uint32 `structs:"ifId" lean:"-"`

	// An array of opaque identifiers. See sock_diag(7)
	Cookie [2]uint32 `structs:"cookie" lean:"-"`
}

// Socket mirrors diag.Socket so as to add struct tags for marshalling.
type Socket struct {
	Family  uint8  `structs:"family" lean:"-"`
	State   uint8  `structs:"state" lean:"-"`
	Timer   uint8  `structs:"timer" lean:"-"`
	Retrans uint8  `structs:"retrans" lean:"-"`
	ID      SockID `structs:"id" lean:"-"`
	Expires uint32 `structs:"expires" lean:"-"`
	RQueue  uint32 `structs:"rQueue" lean:"-"`
	WQueue  uint32 `structs:"wQueue" lean:"-"`
	UID     uint32 `structs:"uid" lean:"-"`
	INode   uint32 `structs:"iNode" lean:"-"`
}

func (i *Socket) String() string {
	return fmt.Sprintf("%#v", *i)
}

// TCPInfo is the linux defined structure returned in RouteAttr INET_DIAG_INFO messages.
// It corresponds to the struct tcp_info in [0]. This struct definition has been plundered
// from github.com/m-lab/tcp-info.
//
// 0: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/tcp.h
type TCPInfo struct {
	State       uint8 `structs:"state" lean:"-"`
	Ca_state    uint8 `structs:"caState" lean:"-"`
	Retransmits uint8 `structs:"retransmits"`
	Probes      uint8 `structs:"probes" lean:"-"`
	Backoff     uint8 `structs:"backoff" lean:"-"`

	// See https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/tcp.h#L166
	// for a list of possible values.
	Options                   uint8  `structs:"options" lean:"-"`
	Snd_wscale                uint8  `structs:"sndWscale" lean:"-"` // no uint4
	Rcv_wscale                uint8  `structs:"rcvdWscale" lean:"-"`
	Delivery_rate_app_limited uint8  `structs:"deliveryRateAppLimited" lean:"-"`
	Fastopen_client_fail      uint8  `structs:"fastOpenClientFail" lean:"-"`
	Rto                       uint32 `structs:"rto" lean:"-"`
	Ato                       uint32 `structs:"ato" lean:"-"`
	Snd_mss                   uint32 `structs:"sndMss" lean:"sndMss"`
	Rcv_mss                   uint32 `structs:"rcvMss" lean:"-"`
	Unacked                   uint32 `structs:"unAcked" lean:"-"`
	Sacked                    uint32 `structs:"sAcked" lean:"-"`
	Lost                      uint32 `structs:"lost" lean:"-"`
	Retrans                   uint32 `structs:"retrans" lean:"-"`
	Fackets                   uint32 `structs:"fAckets" lean:"-"`

	/* Times. */
	// These seem to be elapsed time, so they increase on almost every sample.
	// We can probably use them to get more info about intervals between samples.
	Last_data_sent uint32 `structs:"lastDataSent" lean:"-"`
	Last_ack_sent  uint32 `structs:"lastAckSent" lean:"-"`
	Last_data_recv uint32 `structs:"lastDataRecv" lean:"-"`
	Last_ack_recv  uint32 `structs:"lastAckRecv" lean:"-"`

	/* Metrics. */
	Pmtu            uint32 `structs:"pMtu" lean:"pMtu"`
	Rcv_ssthresh    uint32 `structs:"rcvSsThresh" lean:"-"`
	Rtt             uint32 `structs:"rtt" lean:"rtt"`
	Rttvar          uint32 `structs:"rttVar" lean:"rttVar"`
	Snd_ssthresh    uint32 `structs:"sndSsThresh" lean:"sndSsThresh"`
	Snd_cwnd        uint32 `structs:"sndCwnd" lean:"sndCwnd"`
	Advmss          uint32 `structs:"advMss" lean:"advMss"`
	Reordering      uint32 `structs:"reordering" lean:"-"`
	Rcv_rtt         uint32 `structs:"rcvRtt" lean:"-"`
	Rcv_space       uint32 `structs:"rcvSpace" lean:"-"`
	Total_retrans   uint32 `structs:"totalRetrans" lean:"-"`
	Pacing_rate     uint64 `structs:"pacingRate" lean:"-"`
	Max_pacing_rate uint64 `structs:"maxPacingRate" lean:"-"`

	/* RFC4898 tcpEStatsAppHCThruOctetsAcked */
	Bytes_acked uint64 `structs:"bytesAcked" lean:"-"`
	/* RFC4898 tcpEStatsAppHCThruOctetsReceived */
	Bytes_received uint64 `structs:"bytesRecv" lean:"-"`
	/* RFC4898 tcpEStatsPerfSegsOut */
	Segs_out uint32 `structs:"segsOut" lean:"-"`
	/* RFC4898 tcpEStatsPerfSegsIn */
	Segs_in       uint32 `structs:"segsIn" lean:"-"`
	Notsent_bytes uint32 `structs:"notsentBytes" lean:"-"`
	Min_rtt       uint32 `structs:"minRtt" lean:"minRtt"`
	/* RFC4898 tcpEStatsDataSegsIn */
	Data_segs_in uint32 `structs:"dataSegsIn" lean:"-"`
	/* RFC4898 tcpEStatsDataSegsOut */
	Data_segs_out uint32 `structs:"dataSegsOut" lean:"-"`

	Delivery_rate uint64 `structs:"deliveryRate" lean:"deliveryRate"`

	/* Time (usec) busy sending data */
	Busy_time uint64 `structs:"busyTime" lean:"-"`
	/* Time (usec) limited by receive window */
	Rwnd_limited uint64 `structs:"rwndLimited" lean:"-"`
	/* Time (usec) limited by send buffer */
	Sndbuf_limited uint64 `structs:"sndBufLimited" lean:"-"`

	Delivered    uint32 `structs:"delivered" lean:"-"`
	Delivered_ce uint32 `structs:"deliveredCe" lean:"-"`

	/* RFC4898 tcpEStatsPerfHCDataOctetsOut */
	Bytes_sent uint64 `structs:"bytesSent" lean:"bytesSent"`
	/* RFC4898 tcpEStatsPerfOctetsRetrans */
	Bytes_retrans uint64 `structs:"bytesRetrans" lean:"-"`
	/* RFC4898 tcpEStatsStackDSACKDups */
	Dsack_dups uint32 `structs:"dsAckDups" lean:"-"`
	/* reordering events seen */
	Reord_seen uint32 `structs:"reordSeen" lean:"-"`
	/* Out-of-order packets received */
	Rcv_ooopack uint32 `structs:"rcvOooPack" lean:"-"`
	/* peer's advertised receive window after scaling (bytes) */
	Snd_wnd uint32 `structs:"sndWnd" lean:"-"`
}

func (i *TCPInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// Cong encodes the TCP Congestion Avoidance (CA) algorithm
// in use by a given TCP socket.
type Cong struct {
	Algorithm string `json:"algorithm"`
}

func (i *Cong) String() string {
	return i.Algorithm
}

// State is the enumeration of TCP states. See [0, 1].
//
// 0: https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/
// 1: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/tcp.h
type State int32

func (x State) String() string {
	s, ok := stateName[x]
	if !ok {
		return fmt.Sprintf("UNKNOWN_STATE_%d", x)
	}
	return s
}

// VegasInfo implements the struct associated with INET_DIAG_VEGASINFO, corresponding with
// linux struct tcpvegas_info [0].
// 0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/inet_diag.h
type VegasInfo struct {
	Enabled  uint32 `structs:"enabled" lean:"-"`
	RTTCount uint32 `structs:"rttCount" lean:"-"`
	RTT      uint32 `structs:"rtt" lean:"-"`
	MinRTT   uint32 `structs:"minRtt" lean:"-"`
}

func (i *VegasInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// DCTCPInfo implements the struct associated with INET_DIAG_DCTCPINFO, corresponding with
// linux struct tcp_dctcp_info [0].
// 0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/inet_diag.h
type DCTCPInfo struct {
	Enabled uint16 `structs:"enabled" lean:"-"`
	CEState uint16 `structs:"ceState" lean:"-"`
	Alpha   uint32 `structs:"alpha" lean:"-"`
	ABEcn   uint32 `structs:"abeCn" lean:"-"`
	ABTot   uint32 `structs:"abTot" lean:"-"`
}

func (i *DCTCPInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// TOS encodes the the TOS information associated with INET_DIAG_TOS.
type TOS struct {
	TOS uint8 `structs:"tos" lean:"-"`
}

func (i *TOS) String() string {
	return fmt.Sprintf("%#v", *i)
}

// SkMemInfo encodes the socket memory information set forth in sock_diag(7).
type SkMemInfo struct {
	// The amount of data in receive queue.
	RMemAlloc uint32 `structs:"rMemAlloc" lean:"-"`

	// The receive socket buffer as set by SO_RCVBUF.
	RcvBuff uint32 `structs:"rcvBuff" lean:"-"`

	// The amount of data in send queue.
	WMemAlloc uint32 `structs:"WMemAlloc" lean:"-"`

	// The send socket buffer as set by SO_SNDBUF.
	SndBuff uint32 `structs:"sndBuff" lean:"-"`

	// The amount of memory scheduled for future use (TCP only).
	FwdAlloc uint32 `structs:"fwdAlloc" lean:"-"`

	// The amount of data queued by TCP, but not yet sent.
	WMemQueued uint32 `structs:"wMemQueued" lean:"-"`

	// The amount of memory allocated for the socket's service needs (e.g., socket filter).
	OptMem uint32 `structs:"optMem" lean:"-"`

	// The amount of packets in the backlog (not yet processed).
	Backlog uint32 `structs:"backlog" lean:"-"`

	// Check https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
	Drops uint32 `structs:"drops" lean:"-"`
}

func (i *SkMemInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// MemInfo implements the struct associated with INET_DIAG_MEMINFO, corresponding with
// linux struct inet_diag_meminfo [0].
// 0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/inet_diag.h
type MemInfo struct {
	RMem uint32 `structs:"rMem" lean:"-"`
	WMem uint32 `structs:"wMem" lean:"-"`
	FMem uint32 `structs:"fMem" lean:"-"`
	TMem uint32 `structs:"tMem" lean:"-"`
}

func (i *MemInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// TCPBBRInfo implements the struct associated with INET_DIAG_BBRINFO attribute, corresponding with
// linux struct tcp_bbr_info [0].
// 0: https://elixir.bootlin.com/linux/v5.14/source/include/uapi/linux/inet_diag.h
type TCPBBRInfo struct {
	// Max-filtered BW (app throughput) estimate in bytes/second
	BBRBW uint64 `structs:"bbrBW" lean:"-"`

	// Min-filtered RTT in uSec
	BBRMinRTT uint32 `structs:"bbrMinRTT" lean:"-"`

	// Pacing gain shifted left 8 bits
	BBRPacingGain uint32 `structs:"bbrPacingGain" lean:"-"`

	// Cwnd gain shifted left 8 bits
	BBRCwndGain uint32 `structs:"bbrCwndGain" lean:"-"`
}

func (i *TCPBBRInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}
