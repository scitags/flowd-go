package enrichment

import (
	"time"

	"github.com/scitags/flowd-go/types"
)

// Enricher specifies the behaviour of a source of enrichment
// providing socket-level information for TCP connections.
type Enricher interface {
	Run(<-chan struct{})
	WatchFlow(types.FlowID) (*Poller, error)
	ForgetFlow(types.FlowID) (time.Time, bool)
	Cleanup() error
	String() string
}
