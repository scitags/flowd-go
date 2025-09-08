//go:build linux && ebpf

package marker

import (
	"bytes"
	"embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/cilium/ebpf"
)

//go:embed progs/*.o
var progs embed.FS

type MarkingStrategy string

const (
	Label               MarkingStrategy = "label"
	HopByHop                            = "hopByHop"
	Destination                         = "destination"
	HopByHopDestination                 = "hopByHopDestination"

	PROG_NAME string = "marker"
	MAP_NAME  string = "flowLabels"
)

var markingStrategyMap = map[string]MarkingStrategy{
	strings.ToLower("label"): Label,
	strings.ToLower("hbh"):   HopByHop,
	strings.ToLower("do"):    Destination,
	strings.ToLower("hbhdo"): HopByHopDestination,
}

func craftProgramPath(strategy MarkingStrategy, matchAll bool, debug bool) string {
	progPath := "progs/marker-"

	for k, v := range markingStrategyMap {
		if v == strategy {
			progPath += k
			break
		}
	}

	if matchAll {
		progPath += "-all"
	}

	if debug {
		progPath += "-dbg"
	}

	progPath += ".bpf.o"

	slog.Debug("built program path", "path", progPath)

	return progPath
}

func chooseProgram(strategy MarkingStrategy, matchAll bool, debug bool) ([]byte, error) {
	return progs.ReadFile(craftProgramPath(strategy, matchAll, debug))
}

func loadProg(rawProg []byte) (*ebpf.Collection, error) {
	progSpec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(rawProg))
	if err != nil {
		return nil, fmt.Errorf("error parsing the eBPF program: %w", err)
	}

	// We can modify the spec as we want: nothing's been loaded into the kernel yet
	// progSpec.RewriteConstants()

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
