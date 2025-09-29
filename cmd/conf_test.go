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
		p int
		s *skops.Config
		n *netlink.Config
	}{
		"period.yaml": {
			p: 10,
			s: nil,
			n: nil,
		},
		"defaults.yaml": {
			p: 1000,
			s: &skops.DefaultConfig,
			n: &netlink.DefaultConfig,
		},
		"populated.yaml": {
			p: 1234,
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
		if f.Name() == "none.yaml" {
			continue
		}

		got, err := ReadConf(testDir + "/" + f.Name())
		if err != nil {
			t.Fatalf("error parsing %q: %v", f.Name(), err)
		}

		t.Logf("\n%s", got)

		want, ok := tests[f.Name()]
		if !ok {
			t.Fatalf("got no want for %q", f.Name())
		}

		if !cmp.Equal(got.Enrichers.SkOps, want.s) {
			t.Fatalf("%s: got %v; want %v for skops", f.Name(), got.Enrichers.SkOps, want.s)
		}

		if !cmp.Equal(got.Enrichers.Netlink, want.n) {
			t.Fatalf("%s: got %v; want %v for netlink", f.Name(), got.Enrichers.Netlink, want.n)
		}

		if *got.Enrichers.Period != want.p {
			t.Fatalf("%s: got %v; want %v for period", f.Name(), *got.Enrichers.Period, want.p)
		}
	}
}

func TestNoEnrichment(t *testing.T) {
	got, err := ReadConf("testdata/enrichment/none.yaml")
	if err != nil {
		t.Fatalf("error parsing none.yaml: %v", err)
	}

	if got.Enrichers != nil {
		t.Errorf("got %v; want nil", got.Enrichers)
	}
}
