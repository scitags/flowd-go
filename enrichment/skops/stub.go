//go:build darwin

package skops

type FlowSpec struct {
	DstPort uint32
	SrcPort uint32
}

type FlowMap struct{}

func (fm *FlowMap) Update(foo, fee interface{}) interface{} { return nil }

type EbpfEnricher struct {
	FlowMap FlowMap
}

func NewEnricher(pollingInterval uint64) (*EbpfEnricher, error) { return nil, nil }

func (e *EbpfEnricher) Run(done <-chan struct{}, outChan chan<- TcpInfo) {}
