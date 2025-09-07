//go:build linux

package ebpf

import (
	"testing"
)

func TestEmbeddedProgs(t *testing.T) {
	tests := []struct {
		s    MarkingStrategy
		all  bool
		dbg  bool
		want string
	}{
		{Label, false, false, "progs/marker-label.bpf.o"},
		{Label, false, true, "progs/marker-label-dbg.bpf.o"},
		{Label, true, false, "progs/marker-label-all.bpf.o"},
		{Label, true, true, "progs/marker-label-all-dbg.bpf.o"},

		{HopByHop, false, false, "progs/marker-hbh.bpf.o"},
		{HopByHop, false, true, "progs/marker-hbh-dbg.bpf.o"},
		{HopByHop, true, false, "progs/marker-hbh-all.bpf.o"},
		{HopByHop, true, true, "progs/marker-hbh-all-dbg.bpf.o"},

		{Destination, false, false, "progs/marker-do.bpf.o"},
		{Destination, false, true, "progs/marker-do-dbg.bpf.o"},
		{Destination, true, false, "progs/marker-do-all.bpf.o"},
		{Destination, true, true, "progs/marker-do-all-dbg.bpf.o"},

		{HopByHopDestination, false, false, "progs/marker-hbhdo.bpf.o"},
		{HopByHopDestination, false, true, "progs/marker-hbhdo-dbg.bpf.o"},
		{HopByHopDestination, true, false, "progs/marker-hbhdo-all.bpf.o"},
		{HopByHopDestination, true, true, "progs/marker-hbhdo-all-dbg.bpf.o"},
	}

	for _, test := range tests {
		out := craftProgramPath(test.s, test.all, test.dbg)

		if out != test.want {
			t.Errorf("want %s, got %s", test.want, out)
			continue
		}

		_, err := progs.ReadFile(out)
		if err != nil {
			t.Errorf("error opening the embedded program: %v", err)
		}
	}
}

func TestLoadProg(t *testing.T) {
	rawProg, err := progs.ReadFile("progs/marker-label.bpf.o")
	if err != nil {
		t.Fatalf("error reading the raw eBPF program: %v", err)
	}

	coll, err := loadProg(rawProg)
	if err != nil {
		t.Fatalf("error loading the eBPF program into the kernel: %v", err)
	}
	defer coll.Close()
}
