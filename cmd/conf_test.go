package main

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/scitags/flowd-go/enrichment/netlink"
	"github.com/scitags/flowd-go/enrichment/skops"
)

func TestYAMLAndJSON(t *testing.T) {
	testDir := "testdata/yaml_json"
	d, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("error reading testdata: %v", err)
	}

	confs := []*Config{}
	for _, n := range d {
		c, err := ReadConf(testDir + "/" + n.Name())
		if err != nil {
			t.Fatalf("error parsing %q: %v", n.Name(), err)
		}
		t.Logf("%s:\n%s", n.Name(), c)
		confs = append(confs, c)
	}

	if len(confs) != 2 {
		t.Fatalf("expected two configurations but got %d", len(confs))
	}

	if !cmp.Equal(confs[0], confs[1]) {
		t.Errorf("configurations are not equal")
	}
}

func TestEnrichment(t *testing.T) {
	testDir := "testdata/enrichment"
	d, err := os.ReadDir(testDir)
	if err != nil {
		t.Fatalf("error reading configuration directory: %v", err)
	}

	tests := map[string]struct {
		s *skops.Config
		n *netlink.Config
	}{
		"defaults.yaml": {
			s: &skops.DefaultConfig,
			n: &netlink.DefaultConfig,
		},
		"populated.yaml": {
			s: &skops.Config{
				PollingInterval: 1234 * skops.NS_PER_MS,
				CgroupPath:      "/",
				ProgramPath:     "/",
				DebugMode:       true,
				RawStrategy:     "poll",
				Strategy:        skops.Poll,
				CacheCapacity:   10,
			},
			n: &netlink.Config{
				Protocol:      255,
				Ext:           255,
				State:         1234,
				CacheCapacity: 10,
				Period:        1234,
			},
		},
	}

	for _, f := range d {
		got, err := ReadConf(testDir + "/" + f.Name())
		if err != nil {
			t.Fatalf("error parsing %q: %v", f.Name(), err)
		}

		t.Logf("\n%s", got)

		want, ok := tests[f.Name()]
		if !ok {
			t.Fatalf("got no want for %q", f.Name())
		}

		if !cmp.Equal(got.Backends.Firefly.SkOps, want.s) {
			t.Fatalf("%s: got %v; want %v for skops", f.Name(), got.Backends.Firefly.SkOps, want.s)
		}

		if !cmp.Equal(got.Backends.Firefly.Netlink, want.n) {
			t.Fatalf("%s: got %v; want %v for netlink", f.Name(), got.Backends.Firefly.Netlink, want.n)
		}
	}
}
