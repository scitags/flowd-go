package skops

import "strings"

//go:generate go tool golang.org/x/tools/cmd/stringer -type=Strategy

type Config struct {
	// eBPF program's polling interval in ns. Note that if
	// the loaded program's not polling, this option's
	// silently ignored.
	PollingInterval uint64

	// Path to the cgroup to attach the eBPF program to.
	// If left empty, the cgroup flowd-go's PID belongs
	// to will be used.
	CgroupPath string

	// Path to an eBPF program to leverage for gathering data.
	// If left empty, an embedded program will be used instead.
	ProgramPath string

	// Data acquisition strategy. Check the documentation for
	// an up-to-date list of available options.
	Strategy Strategy

	// Whether to enable debugging output of the eBPF program
	// to query with bpftool(8) and similar tools. Beware that
	// leveraging this option causes a noticeable performance
	// degradation.
	DebugMode bool
}

// DefaultConfig provides sane defaults for EbpfEnrichers.
var DefaultConfig = Config{
	// Poll with a 1 second frequency
	PollingInterval: 1000 * NS_PER_MS,

	// Catch-all cgroup
	CgroupPath: "/sys/fs/cgroup",

	// Use embedded programs
	ProgramPath: "",

	// Poll for data
	Strategy: Strategy(Poll),

	// Don't printk information
	DebugMode: false,
}

type Strategy int

const (
	// Poll socket structures at an specified interval, including
	// TCP state transitions.
	Poll Strategy = iota

	// Gather data on TCP state transitions, including
	// connection closures
	Transition
)

func ParseStrategy(s string) (Strategy, bool) {
	ss, ok := strategyMap[strings.ToLower(s)]
	return ss, ok
}

// strategy map associates available strategies to their string representation.
var strategyMap = func() map[string]Strategy {
	m := make(map[string]Strategy)
	for i := Poll; i <= Transition; i++ {
		m[strings.ToLower(i.String())] = i
	}
	return m
}()
