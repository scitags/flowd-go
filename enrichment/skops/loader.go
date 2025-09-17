//go:build linux && ebpf

package skops

import (
	"bytes"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
)

const PROG_NAME string = "connTracker"
const RINGBUFF_NAME string = "tcpStats"
const MAP_NAME string = "flowsToFollow"

func setGlobalVariable(coll *ebpf.CollectionSpec, gvar string, val any) error {
	v, ok := coll.Variables[gvar]
	if !ok {
		return fmt.Errorf("couldn't find %q variable", gvar)
	}
	slog.Debug("setting global variable", "gvar", gvar, "val", val)
	v.Set(val)

	return nil
}

// consider unifying this function with the one from the eBPF backend!
func loadProg(rawProg []byte, pollingInterval uint64) (*ebpf.Collection, error) {
	progSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(rawProg))
	if err != nil {
		return nil, fmt.Errorf("error parsing the eBPF program: %w", err)
	}

	if err := setGlobalVariable(progSpec, "POLLING_INTERVAL_NS", pollingInterval); err != nil {
		return nil, err
	}
	if err := setGlobalVariable(progSpec, "CONFIG_HZ", getConfigHz()); err != nil {
		return nil, err
	}

	// Time to load the program and assorted resources!
	coll, err := ebpf.NewCollectionWithOptions(progSpec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// bits ebpf.LogLevelBranch | ebpf.LogLevelInstruction make the output very verbose!
			LogLevel: ebpf.LogLevelStats,

			// Leverage KernelTypes to load BTF information from places other than vmlinux!
			// This is particularly useful for containers and such...
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

	_, ok = coll.Maps[MAP_NAME]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("map %q hasn't been loaded", MAP_NAME)
	}

	_, ok = coll.Maps[RINGBUFF_NAME]
	if !ok {
		coll.Close()
		return nil, fmt.Errorf("ringbuff %q hasn't been loaded", MAP_NAME)
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
