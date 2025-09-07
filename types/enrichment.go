package types

import (
	"encoding/json"
	"fmt"

	"github.com/fatih/structs"
	"github.com/vishvananda/netlink"
)

// Map validTags encodes valid struct tags allowing for
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

// Struct Enrichment encodes all the connection enrichment information for a
// particular flow. The addition of several struct tags allows for a precise
// control over what fields are marshalled.
type Enrichment struct {
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

// Struct compatibilityEnrichment serves as a buffer between flowd-go's
// native representation (i.e. Enrichment) and legacy flowd's structure
// for connection enrichment data. As seen on [0], flowd's logic will
// parse the output of ss(8) applying the transformations and names
// specified in the `info_refine_tabl` dictionary [0]. This struct implements
// the transformations defined through `info_refine_tabl` so as to generate
// a compliant object encoding connection enrichment information.
//
// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
type compatibilityEnrichment struct {
	State   string `json:"state"`
	Pmtu    uint32 `json:"pmtu"`
	Retrans uint32 `json:"retrans"`
	Ato     uint32 `json:"ato"`
	Rto     uint32 `json:"rto"`

	Snd_wscale   uint8  `json:"snd_wscale"`
	Rcv_wscale   uint8  `json:"rcv_wscale"`
	Snd_mss      uint32 `json:"snd_mss"`
	Snd_cwnd     uint32 `json:"snd_cwnd"`
	Snd_ssthresh uint32 `json:"snd_ssthresh"`

	Rtt       uint32 `json:"rtt"`
	Rttvar    uint32 `json:"rttvar"`
	Rcv_rtt   uint32 `json:"rcv_rtt"`
	Rcv_space uint32 `json:"rcv_space"`

	Options []string `json:"opts"`

	Last_data_sent uint32 `json:"last_data_sent"`

	Rcv_ssthresh uint32 `json:"rcv_ssthresh"`

	Segs_in       uint32 `json:"segs_in"`
	Segs_out      uint32 `json:"segs_out"`
	Data_segs_in  uint32 `json:"data_segs_in"`
	Data_segs_out uint32 `json:"data_segs_out"`

	Lost          uint32 `json:"lost"`
	Notsent_bytes uint32 `json:"notsent_bytes"`

	Rcv_mss uint32 `json:"rcv_mss"`

	Pacing_rate uint64 `json:"pacing_rate"`
	Retransmits uint8  `json:"retransmits"`

	Min_rtt      uint32 `json:"min_rtt"`
	Rwnd_limited uint64 `json:"rwnd_limited"`

	Max_pacing_rate uint64 `json:"max_pacing_rate"`

	Probes     uint8  `json:"probes"`
	Reordering uint32 `json:"reordering"`

	Last_data_recv uint32 `json:"last_data_recv"`
	Bytes_received uint64 `json:"bytes_received"`

	Fackets uint32 `json:"fackets"`

	Last_ack_recv uint32 `json:"last_ack_recv"`
	Last_ack_sent uint32 `json:"last_ack_sent"`

	Unacked uint32 `json:"unacked"`
	Sacked  uint32 `json:"sacked"`

	Bytes_acked uint64 `json:"bytes_acked"`

	Delivery_rate_app_limited uint8  `json:"delivery_rate_app_limited"`
	Delivery_rate             uint64 `json:"delivery_rate"`

	Sndbuf_limited uint64 `json:"sndbuf_limited"`

	Ca_state      uint8  `json:"ca_state"`
	Busy_time     uint64 `json:"busy_time"`
	Total_retrans uint32 `json:"total_retrans"`

	Advmss  uint32 `json:"advmss"`
	Backoff uint8  `json:"backoff"`
}

// NewCompatibilityEnrichment populates a compatibilityEnrichment
// struct based on the contents of the passed Enrichment struct. In doing
// so, some fields will be (slightly) processed so as to adhere with the
// format expected by the legacy flowd-go implementation. These transformations
// are those that can be derived from the `info_refine_tabl` dictionary [0]
// present in flowd's implementation.
//
// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
func NewCompatibilityEnrichment(e *Enrichment) compatibilityEnrichment {
	to1k := func(og uint32) uint32 { return og / 1000 }

	processState := func(s uint8) string {
		ss, ok := compatibleStateNames[State(s)]
		if !ok {
			return "invalid"
		}
		return ss
	}

	processOpts := func(opts uint8) []string {
		parsed := []string{}

		if opts&TCPI_OPT_TIMESTAMPS != 0 {
			parsed = append(parsed, "ts")
		}
		if opts&TCPI_OPT_SACK != 0 {
			parsed = append(parsed, "sack")
		}
		if opts&TCPI_OPT_ECN != 0 {
			parsed = append(parsed, "ecn")
		}

		return parsed
	}

	ce := compatibilityEnrichment{
		State:   processState(e.TCPInfo.State),
		Pmtu:    e.TCPInfo.Pmtu,
		Retrans: e.TCPInfo.Retrans,
		Ato:     to1k(e.TCPInfo.Ato),
		Rto: func(og uint32) uint32 {
			if og != 3000000 {
				return to1k(og)
			}
			return 0
		}(e.TCPInfo.Rto),
		Snd_wscale: e.TCPInfo.Snd_wscale,
		Rcv_wscale: e.TCPInfo.Rcv_wscale,
		Snd_mss:    e.TCPInfo.Snd_mss,
		Snd_cwnd:   e.TCPInfo.Snd_cwnd,
		Snd_ssthresh: func(og uint32) uint32 {
			if og < 0xFFFF {
				return og
			}
			return 0
		}(e.TCPInfo.Snd_ssthresh),

		Rtt:       to1k(e.TCPInfo.Rtt),
		Rttvar:    to1k(e.TCPInfo.Rttvar),
		Rcv_rtt:   to1k(e.TCPInfo.Rcv_rtt),
		Rcv_space: e.TCPInfo.Rcv_space,

		Options: processOpts(e.TCPInfo.Options),

		Last_data_sent: e.TCPInfo.Last_data_sent,
		Rcv_ssthresh:   e.TCPInfo.Rcv_ssthresh,

		Segs_in:       e.TCPInfo.Segs_in,
		Segs_out:      e.TCPInfo.Segs_out,
		Data_segs_in:  e.TCPInfo.Data_segs_in,
		Data_segs_out: e.TCPInfo.Data_segs_out,

		Lost:                      e.TCPInfo.Lost,
		Notsent_bytes:             e.TCPInfo.Notsent_bytes,
		Rcv_mss:                   e.TCPInfo.Rcv_mss,
		Pacing_rate:               e.TCPInfo.Pacing_rate,
		Retransmits:               e.TCPInfo.Retransmits,
		Min_rtt:                   e.TCPInfo.Min_rtt,
		Rwnd_limited:              e.TCPInfo.Rwnd_limited,
		Max_pacing_rate:           e.TCPInfo.Max_pacing_rate,
		Probes:                    e.TCPInfo.Probes,
		Reordering:                e.TCPInfo.Reordering,
		Last_data_recv:            e.TCPInfo.Last_data_recv,
		Bytes_received:            e.TCPInfo.Bytes_received,
		Fackets:                   e.TCPInfo.Fackets,
		Last_ack_recv:             e.TCPInfo.Last_ack_recv,
		Last_ack_sent:             e.TCPInfo.Last_ack_sent,
		Unacked:                   e.TCPInfo.Unacked,
		Sacked:                    e.TCPInfo.Sacked,
		Bytes_acked:               e.TCPInfo.Bytes_acked,
		Delivery_rate_app_limited: e.TCPInfo.Delivery_rate_app_limited,
		Delivery_rate:             e.TCPInfo.Delivery_rate,
		Sndbuf_limited:            e.TCPInfo.Sndbuf_limited,
		Ca_state:                  e.TCPInfo.Ca_state,
		Busy_time:                 e.TCPInfo.Busy_time,
		Total_retrans:             e.TCPInfo.Total_retrans,
		Advmss:                    e.TCPInfo.Advmss,
		Backoff:                   e.TCPInfo.Backoff,
	}
	return ce
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
func (e *Enrichment) MarshalJSON() ([]byte, error) {
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

// Socket simply embeds netlink.Socket to allow us to expose the
// private deserialize method.
type Socket struct {
	netlink.Socket
}

func (i *Socket) String() string {
	return fmt.Sprintf("%#v", *i)
}

// TCPInfo is the linux defined structure returned in RouteAttr INET_DIAG_INFO messages.
// It corresponds to the struct tcp_info in [0]. This struct definition has been plundered
// from github.com/m-lab/tcp-info.
// References:
//
//	0: https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/uapi/linux/tcp.h
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

type Cong struct {
	Algorithm string `json:"algorithm"`
}

func (i *Cong) String() string {
	return i.Algorithm
}

// State is the enumeration of TCP states.
// https://datatracker.ietf.org/doc/draft-ietf-tcpm-rfc793bis/
// and uapi/linux/tcp.h
type State int32

func (x State) String() string {
	s, ok := stateName[x]
	if !ok {
		return fmt.Sprintf("UNKNOWN_STATE_%d", x)
	}
	return s
}

// VegasInfo implements the struct associated with INET_DIAG_VEGASINFO, corresponding with
// linux struct tcpvegas_info in uapi/linux/inet_diag.h.
type VegasInfo struct {
	Enabled  uint32 `json:"enabled"`
	RTTCount uint32 `json:"rttCount"`
	RTT      uint32 `json:"rtt"`
	MinRTT   uint32 `json:"minRtt"`
}

func (i *VegasInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// DCTCPInfo implements the struct associated with INET_DIAG_DCTCPINFO attribute, corresponding with
// linux struct tcp_dctcp_info in uapi/linux/inet_diag.h.
type DCTCPInfo struct {
	Enabled uint16 `json:"enabled"`
	CEState uint16 `json:"ceState"`
	Alpha   uint32 `json:"alpha"`
	ABEcn   uint32 `json:"abeCn"`
	ABTot   uint32 `json:"abTot"`
}

func (i *DCTCPInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

type TOS struct {
	TOS uint8 `json:"tos"`
}

func (i *TOS) String() string {
	return fmt.Sprintf("%#v", *i)
}

// Taken from sock_diag(7)
type SkMemInfo struct {
	// The amount of data in receive queue.
	RMemAlloc uint32 `json:"rMemAlloc"`
	// The receive socket buffer as set by SO_RCVBUF.
	RcvBuff uint32 `json:"rcvBuff"`
	// The amount of data in send queue.
	WMemAlloc uint32 `json:"WMemAlloc"`
	// The send socket buffer as set by SO_SNDBUF.
	SndBuff uint32 `json:"sndBuff"`
	// The amount of memory scheduled for future use (TCP only).
	FwdAlloc uint32 `json:"fwdAlloc"`
	// The amount of data queued by TCP, but not yet sent.
	WMemQueued uint32 `json:"wMemQueued"`
	// The amount of memory allocated for the socket's service needs (e.g., socket filter).
	OptMem uint32 `json:"optMem"`
	// The amount of packets in the backlog (not yet processed).
	Backlog uint32 `json:"backlog"`
	// Check https://manpages.debian.org/stretch/manpages/sock_diag.7.en.html
	Drops uint32 `json:"drops"`
}

func (i *SkMemInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// MemInfo implements the struct associated with INET_DIAG_MEMINFO, corresponding with
// linux struct inet_diag_meminfo in uapi/linux/inet_diag.h.
type MemInfo struct {
	RMem uint32 `json:"rMem"`
	WMem uint32 `json:"wMem"`
	FMem uint32 `json:"fMem"`
	TMem uint32 `json:"tMem"`
}

func (i *MemInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}

// TCPBBRInfo implements the struct associated with INET_DIAG_BBRINFO attribute, corresponding with
// linux struct tcp_bbr_info in uapi/linux/inet_diag.h.
type TCPBBRInfo struct {
	// Max-filtered BW (app throughput) estimate in bytes/second
	BBRBW uint64 `json:"bbrBW"`
	// Min-filtered RTT in uSec
	BBRMinRTT uint32 `json:"bbrMinRTT"`
	// Pacing gain shifted left 8 bits
	BBRPacingGain uint32 `json:"bbrPacingGain"`
	// Cwnd gain shifted left 8 bits
	BBRCwndGain uint32 `json:"bbrCwndGain"`
}

func (i *TCPBBRInfo) String() string {
	return fmt.Sprintf("%#v", *i)
}
