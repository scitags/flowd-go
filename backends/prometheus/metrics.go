package prometheus

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/scitags/flowd-go/types"
)

// Metric labels (note these are **always** strings):
//
//	act: activity id and/or name
//	exp: experiment id and/or name
//	src: source IPv{4,6} address
//	dst: destination IPv{4,6} address
//	flow: source and destination ports formatted as <src:dst>
//
// We haven't included the 'opts' label which would include used TCP/IP options
var baseLabels = []string{"act", "exp", "src", "dst", "flow", "flavour"}

// TODO: Add skmem_* to skOps-gathered structs!
// TODO: flow_tcp_skmem_rmem_alloc
// TODO: flow_tcp_skmem_rcv_buf
// TODO: flow_tcp_skmem_wmem_allow
// TODO: flow_tcp_skmem_snd_buf
// TODO: flow_tcp_skmem_fwd_alloc
// TODO: flow_tcp_skmem_wmem_queued
// TODO: flow_tcp_skmem_opt_mem
// TODO: flow_tcp_skmem_back_log
// TODO: flow_tcp_skmem_sock_drop

// TODO: What does flow_tcp_send map to?

type metrics struct {
	Retrans *prometheus.GaugeVec // *prometheus.CounterVec

	Rto *prometheus.GaugeVec
	Ato *prometheus.GaugeVec

	Rtt    *prometheus.GaugeVec
	RttVar *prometheus.GaugeVec
	RttMin *prometheus.GaugeVec

	Pmtu   *prometheus.GaugeVec
	Mss    *prometheus.GaugeVec
	RcvMss *prometheus.GaugeVec
	AdvMss *prometheus.GaugeVec

	Cwnd *prometheus.GaugeVec

	Ssthresh *prometheus.GaugeVec

	BytesSent     *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]
	BytesAcked    *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]
	BytesReceived *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]

	SegsOut     *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]
	SegsIn      *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]
	DataSegsOut *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]
	DataSegsIn  *prometheus.GaugeVec // These are implemented as ZeroBasedCounter32 [RFC 4502]

	LastSnd *prometheus.GaugeVec // Not sure about these...
	LastRcv *prometheus.GaugeVec // Not sure about these...
	LastAck *prometheus.GaugeVec // Not sure about these...

	PacingRate   *prometheus.GaugeVec
	DeliveryRate *prometheus.GaugeVec

	Delivered *prometheus.GaugeVec

	Busy        *prometheus.GaugeVec
	RwndLimited *prometheus.GaugeVec

	RcvSpace    *prometheus.GaugeVec
	RcvSsthresh *prometheus.GaugeVec

	SndWnd *prometheus.GaugeVec

	CaInfo *prometheus.GaugeVec
}

func newMetrics() *metrics {
	m := &metrics{
		Retrans: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_retrans",
			Help: "Retransmitted packets",
		}, baseLabels),

		Rto: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rto",
			Help: "Retransmit timeout",
		}, baseLabels),
		Ato: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_ato",
			Help: "Delayed ACK timeout",
		}, baseLabels),

		Rtt: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rtt",
			Help: "Round-trip time [us]",
		}, baseLabels),
		RttVar: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rtt_var",
			Help: "Round-trip time variance [us]",
		}, baseLabels),
		RttMin: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_minrtt", // _minrtt for compatibility
			Help: "Minimum round-trip time [us]",
		}, baseLabels),

		Pmtu: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_pmtu",
			Help: "Path MTU [B]",
		}, baseLabels),
		Mss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_mss",
			Help: "Sender's MSS [B]",
		}, baseLabels),
		RcvMss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rcvmss",
			Help: "Receiver's MSS [B]",
		}, baseLabels),
		AdvMss: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_advmss",
			Help: "Advertised MSS [B]",
		}, baseLabels),

		Cwnd: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_cwnd",
			Help: "Sending congestion window [?]",
		}, baseLabels),

		Ssthresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_ssthresh",
			Help: "Slow start size threshold [?]",
		}, baseLabels),

		BytesSent: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_bytes_sent_total", // _total leveraged for backwards compatibility,
			Help: "Total number of bytes sent (RFC4898 tcpEStatsPerfHCDataOctetsOut)",
		}, baseLabels),
		BytesAcked: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_bytes_acked_total", // _total leveraged for backwards compatibility,
			Help: "Total number of bytes acked (RFC4898 tcpEStatsAppHCThruOctetsAcked)",
		}, baseLabels),
		BytesReceived: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_bytes_received_total", // _total leveraged for backwards compatibility,
			Help: "Total number of bytes received (RFC4898 tcpEStatsAppHCThruOctetsReceived)",
		}, baseLabels),

		SegsOut: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_segs_out_total", // _total leveraged for backwards compatibility,
			Help: "Total number of segments sent (RFC4898 tcpEStatsPerfSegsOut)",
		}, baseLabels),
		SegsIn: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_segs_in_total", // _total leveraged for backwards compatibility,
			Help: "Total number of segments received (RFC4898 tcpEStatsPerfSegsOut)",
		}, baseLabels),
		DataSegsOut: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_data_segs_out_total", // _total leveraged for backwards compatibility,
			Help: "Total number of data segments sent (RFC4898 tcpEStatsDataSegsOut)",
		}, baseLabels),
		DataSegsIn: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_data_segs_in_total", // _total leveraged for backwards compatibility,
			Help: "Total number of data segments sent (RFC4898 tcpEStatsDataSegsIn)",
		}, baseLabels),

		LastSnd: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_lastsnd",
			Help: "Now - last sent data packet [ms]",
		}, baseLabels),
		LastRcv: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_lastrcv",
			Help: "Now - last received data packet [ms]",
		}, baseLabels),
		LastAck: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_lastack",
			Help: "Now - last received ACK [ms]",
		}, baseLabels),

		PacingRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_pacing_rate",
			Help: "Pacing rate [Bps]",
		}, baseLabels),
		DeliveryRate: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_delivery_rate",
			Help: "Delivery rate (packets delivered in an interval * MSS / interval) [Bps]",
		}, baseLabels),

		Delivered: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_delivered",
			Help: "Total data packets delivered including retransmits",
		}, baseLabels),

		Busy: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_busy",
			Help: "Time spent sending data or stalled [us]",
		}, baseLabels),
		RwndLimited: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rwnd_limited",
			Help: "Time spent stalled due to the receiver's window [us]",
		}, baseLabels),

		RcvSpace: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rcv_space",
			Help: "Receiver queue space [?]",
		}, baseLabels),
		RcvSsthresh: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rcv_ssthresh",
			Help: "Current window clamp [?]",
		}, baseLabels),

		SndWnd: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rcv_snd_wnd",
			Help: "Peer's advertised receive window after scaling [B]",
		}, baseLabels),

		CaInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flow_tcp_rcv_ca_info",
			Help: "Congestion Algorithm (CA) information",
		}, append(baseLabels, "alg")),
	}

	return m
}

// (Nastily) use reflection to avoid having to manually register everything.
func (m *metrics) register(req prometheus.Registerer) error {
	v := reflect.ValueOf(*m)

	i := 0
	for i = 0; i < v.NumField(); i++ {
		vv, ok := v.Field(i).Interface().(prometheus.Collector)
		if !ok {
			return fmt.Errorf("error casting the interface for index %d", i)
		}
		if err := req.Register(vv); err != nil {
			return fmt.Errorf("error registering index %d: %w", i, err)
		}
	}
	logger.Log(context.Background(), types.LevelTrace, "registered collectors", "i", i)

	return nil
}

func (m *metrics) newLabels(f types.FlowID, t types.Flavour) prometheus.Labels {
	return prometheus.Labels{
		"act":     strconv.FormatUint(uint64(f.Activity), 10),
		"exp":     strconv.FormatUint(uint64(f.Experiment), 10),
		"src":     f.Src.IP.String(),
		"dst":     f.Dst.IP.String(),
		"flow":    fmt.Sprintf("<%d:%d>", f.Src.Port, f.Dst.Port),
		"flavour": t.String(),
	}
}

// Maybe capture labels in a closure?
func (m *metrics) update(labels prometheus.Labels, fi *types.FlowInfo) {
	m.Retrans.With(labels).Add(float64(fi.TCPInfo.Retrans))

	m.Rto.With(labels).Set(float64(fi.TCPInfo.Rto))
	m.Ato.With(labels).Set(float64(fi.TCPInfo.Ato))

	m.Rtt.With(labels).Set(float64(fi.TCPInfo.Rtt))
	m.RttVar.With(labels).Set(float64(fi.TCPInfo.Rttvar))
	m.RttMin.With(labels).Set(float64(fi.TCPInfo.Min_rtt))

	m.Pmtu.With(labels).Set(float64(fi.TCPInfo.Pmtu))
	m.Mss.With(labels).Set(float64(fi.TCPInfo.Snd_mss))
	m.AdvMss.With(labels).Set(float64(fi.TCPInfo.Advmss))

	m.Cwnd.With(labels).Set(float64(fi.TCPInfo.Snd_cwnd))

	m.Ssthresh.With(labels).Set(float64(fi.TCPInfo.Snd_ssthresh))

	m.BytesSent.With(labels).Set(float64(fi.TCPInfo.Bytes_sent))
	m.BytesAcked.With(labels).Set(float64(fi.TCPInfo.Bytes_acked))
	m.BytesReceived.With(labels).Set(float64(fi.TCPInfo.Bytes_received))

	m.SegsOut.With(labels).Set(float64(fi.TCPInfo.Segs_out))
	m.SegsIn.With(labels).Set(float64(fi.TCPInfo.Segs_in))
	m.DataSegsOut.With(labels).Set(float64(fi.TCPInfo.Data_segs_out))
	m.DataSegsIn.With(labels).Set(float64(fi.TCPInfo.Data_segs_in))

	m.LastSnd.With(labels).Set(float64(fi.TCPInfo.Last_data_sent))
	m.LastRcv.With(labels).Set(float64(fi.TCPInfo.Last_data_recv))
	m.LastAck.With(labels).Set(float64(fi.TCPInfo.Last_ack_sent))

	m.PacingRate.With(labels).Set(float64(fi.TCPInfo.Pacing_rate))
	m.DeliveryRate.With(labels).Set(float64(fi.TCPInfo.Delivery_rate))

	m.Delivered.With(labels).Set(float64(fi.TCPInfo.Delivered))

	m.Busy.With(labels).Set(float64(fi.TCPInfo.Busy_time))
	m.RwndLimited.With(labels).Set(float64(fi.TCPInfo.Rwnd_limited))

	m.RcvSpace.With(labels).Set(float64(fi.TCPInfo.Rcv_space))
	m.RcvSsthresh.With(labels).Set(float64(fi.TCPInfo.Rcv_ssthresh))

	m.SndWnd.With(labels).Set(float64(fi.TCPInfo.Snd_wnd))

	// Embed additional CA information in the label
	// Note the underlying map is shared by all With() calls; if
	// we swap it from underneath them we'll run into cardinality
	// issues, so we MUST copy the map to add the additional label.
	newLabels := prometheus.Labels{}
	for k, v := range labels {
		newLabels[k] = v
	}
	newLabels["alg"] = fi.Cong.Algorithm
	m.CaInfo.With(newLabels).Set(1)
}

// Note DeletePartialMatch and Delete have a performance overhead with
// respect to DeleteLabelValues... Consider switching things up when
// the backend's consolidated!
func (m *metrics) delete(labels prometheus.Labels) {
	m.Retrans.DeletePartialMatch(labels)

	m.Rto.DeletePartialMatch(labels)
	m.Ato.DeletePartialMatch(labels)

	m.Rtt.DeletePartialMatch(labels)
	m.RttVar.DeletePartialMatch(labels)
	m.RttMin.DeletePartialMatch(labels)

	m.Pmtu.DeletePartialMatch(labels)
	m.Mss.DeletePartialMatch(labels)
	m.AdvMss.DeletePartialMatch(labels)

	m.Cwnd.DeletePartialMatch(labels)

	m.Ssthresh.DeletePartialMatch(labels)

	m.BytesSent.DeletePartialMatch(labels)
	m.BytesAcked.DeletePartialMatch(labels)
	m.BytesReceived.DeletePartialMatch(labels)

	m.SegsOut.DeletePartialMatch(labels)
	m.SegsIn.DeletePartialMatch(labels)
	m.DataSegsOut.DeletePartialMatch(labels)
	m.DataSegsIn.DeletePartialMatch(labels)

	m.LastSnd.DeletePartialMatch(labels)
	m.LastRcv.DeletePartialMatch(labels)
	m.LastAck.DeletePartialMatch(labels)

	m.PacingRate.DeletePartialMatch(labels)
	m.DeliveryRate.DeletePartialMatch(labels)

	m.Delivered.DeletePartialMatch(labels)

	m.Busy.DeletePartialMatch(labels)
	m.RwndLimited.DeletePartialMatch(labels)

	m.RcvSpace.DeletePartialMatch(labels)
	m.RcvSsthresh.DeletePartialMatch(labels)

	m.SndWnd.DeletePartialMatch(labels)

	m.CaInfo.DeletePartialMatch(labels)
}
