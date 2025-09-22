//go:build linux && ebpf

package marker

import (
	"testing"

	"github.com/scitags/flowd-go/internal/progs"
)

func TestEmbeddedProgs(t *testing.T) {
	tests := []struct {
		s    MarkingStrategy
		all  bool
		dbg  bool
		want string
	}{
		{Label, false, false, "marker-label.bpf.o"},
		{Label, false, true, "marker-label-dbg.bpf.o"},
		{Label, true, false, "marker-label-all.bpf.o"},
		{Label, true, true, "marker-label-all-dbg.bpf.o"},

		{HopByHop, false, false, "marker-hbh.bpf.o"},
		{HopByHop, false, true, "marker-hbh-dbg.bpf.o"},
		{HopByHop, true, false, "marker-hbh-all.bpf.o"},
		{HopByHop, true, true, "marker-hbh-all-dbg.bpf.o"},

		{Destination, false, false, "marker-do.bpf.o"},
		{Destination, false, true, "marker-do-dbg.bpf.o"},
		{Destination, true, false, "marker-do-all.bpf.o"},
		{Destination, true, true, "marker-do-all-dbg.bpf.o"},

		{HopByHopDestination, false, false, "marker-hbhdo.bpf.o"},
		{HopByHopDestination, false, true, "marker-hbhdo-dbg.bpf.o"},
		{HopByHopDestination, true, false, "marker-hbhdo-all.bpf.o"},
		{HopByHopDestination, true, true, "marker-hbhdo-all-dbg.bpf.o"},
	}

	for _, test := range tests {
		out := craftProgramPath(test.s, test.all, test.dbg)

		if out != test.want {
			t.Errorf("want %s, got %s", test.want, out)
			continue
		}

		_, err := progs.GetMarkerProgram(out)
		if err != nil {
			t.Errorf("error opening the embedded program: %v", err)
		}
	}
}

func TestLoadProg(t *testing.T) {
	rawProg, err := progs.GetMarkerProgram("marker-label.bpf.o")
	if err != nil {
		t.Fatalf("error reading the raw eBPF program: %v", err)
	}

	coll, err := loadProg(rawProg)
	if err != nil {
		t.Fatalf("error loading the eBPF program into the kernel: %v", err)
	}
	defer coll.Close()
}
