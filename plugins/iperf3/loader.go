//go:build ebpf

package iperf3

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
)

const (
	PROG_NAME     string = "watcher"
	RINGBUFF_NAME string = "flowNots"
)

func setGlobalVariable(coll *ebpf.CollectionSpec, gvar string, val uint64) error {
	v, ok := coll.Variables[gvar]
	if !ok {
		return fmt.Errorf("couldn't find %q variable", gvar)
	}
	slog.Debug("setting global variable", "gvar", gvar, "val", val)
	if err := v.Set(val); err != nil {
		return fmt.Errorf("error setting the variable: %w", err)
	}

	return nil
}

// consider unifying this function with the one from the eBPF backend!
func loadProg(rawProg []byte, c *Config) (*ebpf.Collection, error) {
	progSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(rawProg))
	if err != nil {
		return nil, fmt.Errorf("error parsing the eBPF program: %w", err)
	}

	if err := setGlobalVariable(progSpec, "MIN_SRC_PORT", uint64(c.MinSourcePort)); err != nil {
		return nil, err
	}

	if err := setGlobalVariable(progSpec, "MAX_SRC_PORT", uint64(c.MaxSourcePort)); err != nil {
		return nil, err
	}

	if err := setGlobalVariable(progSpec, "MIN_DST_PORT", uint64(c.MinDestinationPort)); err != nil {
		return nil, err
	}

	if err := setGlobalVariable(progSpec, "MAX_DST_PORT", uint64(c.MaxDestinationPort)); err != nil {
		return nil, err
	}

	// Time to load the program and assorted resources!
	coll, err := ebpf.NewCollectionWithOptions(progSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogLevel: ebpf.LogLevelStats,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("error loading the eBPF program: %w", err)
	}

	_, ok := coll.Programs[PROG_NAME]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("program %q hasn't been loaded", PROG_NAME)
	}

	_, ok = coll.Maps[RINGBUFF_NAME]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("ringbuff %q hasn't been loaded", RINGBUFF_NAME)
	}

	for n, prog := range coll.Programs {
		slog.Debug("loaded program", "name", n, "type", prog.Type(), "descr", prog.String(), "fd", prog.FD())
		for i, l := range strings.Split(prog.VerifierLog, "\n") {
			if l == "" {
				continue
			}
			slog.Debug("verifier output", "#", i, "l", l)
		}
	}

	for n, m := range coll.Maps {
		slog.Debug("loaded map", "name", n, "type", m.Type(), "descr", m, "fd", m.FD())
	}

	return coll, nil
}

func craftProgramPath(debug bool) (string, error) {
	progPath := "watcher"

	if debug {
		progPath += "-dbg"
	}

	progPath += ".bpf.o"

	slog.Debug("built program path", "path", progPath)

	return progPath, nil
}
