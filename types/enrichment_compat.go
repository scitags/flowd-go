package types

// compatibleStateNames allows for the lookup of TCP states into
// names compatible with the legacy flowd implementation. These names
// have been pulled from [0].
//
// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
var compatibleStateNames = map[State]string{
	TCP_INVALID:     "INVALID",
	TCP_ESTABLISHED: "established",
	TCP_SYN_SENT:    "syn-sent",
	TCP_SYN_RECV:    "syn-recv",
	TCP_FIN_WAIT1:   "fin-wait-1",
	TCP_FIN_WAIT2:   "fin-wait-2",
	TCP_TIME_WAIT:   "time-wait",
	TCP_CLOSE:       "unconnected",
	TCP_CLOSE_WAIT:  "close-wait",
	TCP_LAST_ACK:    "last-ack",
	TCP_LISTEN:      "listening",
	TCP_CLOSING:     "closing",
}

// compatibilityEnrichment serves as a buffer between flowd-go's
// native representation (i.e. FlowInfo) and legacy flowd's structure
// for connection enrichment data. As seen on [0], flowd's logic will
// parse the output of ss(8) applying the transformations and names
// specified in the `info_refine_tabl` dictionary [0]. This struct implements
// the transformations defined through `info_refine_tabl` so as to generate
// a compliant object encoding connection enrichment information.
//
// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
type CompatibilityEnrichment struct {
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

// newCompatibilityEnrichment populates a compatibilityEnrichment
// struct based on the contents of the passed FlowInfo struct. In doing
// so, some fields will be (slightly) processed so as to adhere with the
// format expected by the legacy flowd implementation. These transformations
// are those that can be derived from the `info_refine_tabl` dictionary [0]
// present in flowd's implementation.
//
// 0: https://github.com/scitags/flowd/blob/v1.1.7/scitags/netlink/pyroute_tcp.py
func NewCompatibilityEnrichment(e *FlowInfo) CompatibilityEnrichment {
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

	return CompatibilityEnrichment{
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
}
