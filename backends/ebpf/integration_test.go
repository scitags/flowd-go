//go:build linux

package ebpf

import "testing"

const TARGET_INTERFACE = "lo"

func TestBootstrap(t *testing.T) {
	nlClient, err := NewNetlinkClient()
	if err != nil {
		t.Fatalf("error getting a netlink client: %v", err)
	}
	defer nlClient.Close(false)

	if err := nlClient.CreateFilterQdisc(TARGET_INTERFACE); err != nil {
		t.Fatalf("error creating the qdisc: %v", err)
	}

	rawProg, err := progs.ReadFile("progs/marker-label.bpf.o")
	if err != nil {
		t.Fatalf("error reading the raw eBPF program: %v", err)
	}

	coll, err := loadProg(rawProg)
	if err != nil {
		t.Errorf("error loading the eBPF program into the kernel: %v", err)
	}

	if err := nlClient.AttachEbpfProgram(TARGET_INTERFACE, coll.Programs[PROG_NAME], true); err != nil {
		coll.Close()
		t.Fatalf("error attaching the eBPF program: %v", err)
	}

	// We should close the collection and dismantle the qdisc, but
	// we want to keep it around to inspect the state. We can just
	// clean it up with 'tc qdisc del dev lo clsact' later.
	// defer coll.Close()
}
