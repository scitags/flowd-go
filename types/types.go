package types

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type FlowID struct {
	State       FlowState
	Protocol    Protocol
	Family      Family
	Src         netip.AddrPort
	Dst         netip.AddrPort
	Experiment  uint32
	Activity    uint32
	StartTs     time.Time
	EndTs       time.Time
	CurrentTs   time.Time
	Info        FlowInfo
	Application string

	// Internal communication fields
	FlowInfoChans map[Flavour]chan *FlowInfo
}

func (f FlowID) String() string {
	return fmt.Sprintf(
		"{s: %s, f: %s, src: {i: %s, p: %d}, dst: {i: %s, p: %d}}",
		f.State, f.Family, f.Src.Addr(), f.Src.Port(), f.Dst.Addr(), f.Dst.Port(),
	)
}

type Protocol int

type Family int

type FlowState int

const (
	TCP Protocol = iota
	UDP

	START FlowState = iota
	END
	ONGOING

	IPv4 Family = unix.AF_INET
	IPv6 Family = unix.AF_INET6
)

// TODO: Find a way to make this nicer. Maybe init() functions is the
// TODO: way to go?
var (
	protocolMap = map[string]Protocol{
		"TCP": TCP,
		"UDP": UDP,
	}

	locotorpMap = map[Protocol]string{
		TCP: "tcp",
		UDP: "udp",
	}

	flowMap = map[string]FlowState{
		"START":   START,
		"END":     END,
		"ONGOING": ONGOING,
	}

	wolfMap = map[FlowState]string{
		START:   "start",
		END:     "end",
		ONGOING: "ongoing",
	}

	familyMap = map[string]Family{
		"IPV4": IPv4,
		"IPV6": IPv6,
	}

	ylimafMap = map[Family]string{
		IPv4: "ipv4",
		IPv6: "ipv6",
	}
)

func (p Protocol) String() string {
	return locotorpMap[p]
}

func ParseProtocol(proto string) (Protocol, bool) {
	p, ok := protocolMap[strings.ToUpper(proto)]
	return p, ok
}

func (f Family) String() string {
	return ylimafMap[f]
}

func ParseFamily(proto string) (Family, bool) {
	f, ok := familyMap[strings.ToUpper(proto)]
	return f, ok
}

func (fs FlowState) String() string {
	return wolfMap[fs]
}

func ParseFlowState(flowState string) (FlowState, bool) {
	fs, ok := flowMap[strings.ToUpper(flowState)]
	return fs, ok
}

type Backend interface {
	Run(<-chan struct{}, <-chan FlowID)
	Cleanup() error
	String() string
}

type Plugin interface {
	Run(<-chan struct{}, chan<- FlowID)
	Cleanup() error
	String() string
}
