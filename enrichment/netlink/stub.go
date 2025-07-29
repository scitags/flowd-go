//go:build darwin || !cgo

package netlink

import glowdTypes "github.com/scitags/flowd-go/types"

type InetDiagTCPInfoResp struct{}
type TCPDiagRequest struct{}

func (r *TCPDiagRequest) ExecuteRequest() ([]*glowdTypes.Enrichment, error) {
	return nil, nil
}

func NewTCPDiagRequest(family uint8, srcPort uint16, dstPort uint16) *TCPDiagRequest {
	return &TCPDiagRequest{}
}
