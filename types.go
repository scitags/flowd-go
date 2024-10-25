package glowd

import (
	"net"
	"time"
)

type FlowID struct {
	State      string
	Protocol   Protocol
	Src        IPPort
	Dst        IPPort
	Experiment string
	Activity   string
	StartTs    time.Time
	EndTs      time.Time
	NetLink    string
}

type IPPort struct {
	IP   net.IP
	Port int
}

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

type foo interface {
}
