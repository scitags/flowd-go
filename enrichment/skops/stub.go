//go:build darwin || !ebpf

package skops

type FlowSpec struct {
	DstPort uint32
	SrcPort uint32
}

type TcpInfo struct{}

type FlowMap struct{}

func (fm *FlowMap) Update(foo, fee interface{}) interface{} { return nil }

type EbpfEnricher struct {
	FlowMap FlowMap
}

func NewEnricher(pollingInterval uint64) (*EbpfEnricher, error) { return nil, nil }

func (e *EbpfEnricher) Run(done <-chan struct{}, outChan chan<- TcpInfo) {}
func (e *EbpfEnricher) WatchFlow(flow FlowSpec) error                    { return nil }
