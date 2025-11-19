package processing

import (
	"time"
)

// Enricher specifies the behaviour of a source of enrichment
// providing socket-level information for TCP connections.
type Enricher interface {
	Run(<-chan struct{})
	WatchFlow([]byte) error
	ForgetFlow([]byte) (time.Time, bool)
	Cleanup() error
	String() string
}
