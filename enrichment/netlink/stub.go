//go:build darwin || !cgo

package netlink

type InetDiagTCPInfoResp struct{}
type TCPDiagRequest struct{}

func (r *TCPDiagRequest) ExecuteRequest() ([]*InetDiagTCPInfoResp, error) {
	return nil, nil
}

func NewTCPDiagRequest(family uint8, srcPort uint16, dstPort uint16) *TCPDiagRequest {
	return &TCPDiagRequest{}
}
