package skops

// NS_PER_MS allows us to easily express ms to ns conversions.
const NS_PER_MS uint64 = 1_000_000

// FlowSpec identifies a given socket at L4. It allows us to minimise
// the information exchange across the user-kernel boundary. We use
// uint32s instead of uint16s due to 4-byte alignment constraints.
type FlowSpec struct {
	DstPort uint32
	SrcPort uint32
}
