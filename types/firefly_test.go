package types

import (
	"bytes"
	"net"
	"os"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

func TestFireflyParseIncoming(t *testing.T) {
	testFiles, err := os.ReadDir("testdata")
	if err != nil {
		t.Errorf("couldn't list the testdata directory: %v", err)
	}

	for _, tf := range testFiles {
		if !strings.HasSuffix(tf.Name(), ".firefly") {
			continue
		}

		tfPath := path.Join("testdata", tf.Name())

		data, err := os.ReadFile(tfPath)
		if err != nil {
			t.Errorf("couldn't read %q: %v", t.Name(), err)
		}

		sFirefly := SlimFirefly{}
		if err := sFirefly.Parse(data); err != nil {
			t.Errorf("couldn't parse %q: %v", tfPath, err)
		}

		// fmt.Printf("parsed firefly %q: %+v\n", tfPath, sFirefly)
	}
}

func TestFireflyValidation(t *testing.T) {
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("testdata/firefly-schema-v1.0.0.json")
	if err != nil {
		t.Fatalf("error compiling the schema: %v", err)
	}

	tests := []struct {
		id         FlowID
		nl         *Enrichment
		ebpf       *Enrichment
		withSyslog bool
	}{
		{
			FlowID{
				State:       START,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			nil,
			nil,
			false,
		},
		{
			FlowID{
				State:       ONGOING,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			nil,
			nil,
			false,
		},
		{
			FlowID{
				State:       END,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				EndTs:       time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			nil,
			nil,
			false,
		},
		{
			FlowID{
				State:       START,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			&Enrichment{Verbosity: "lean", Cong: &Cong{Algorithm: "vegas"}},
			nil,
			false,
		},
		{
			FlowID{
				State:       START,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			nil,
			&Enrichment{Verbosity: "lean", Cong: &Cong{Algorithm: "vegas"}},
			false,
		},
		{
			FlowID{
				State:       START,
				Protocol:    TCP,
				Family:      IPv6,
				Src:         IPPort{IP: net.ParseIP("::1"), Port: 1234},
				Dst:         IPPort{IP: net.ParseIP("::1"), Port: 4321},
				StartTs:     time.Now(),
				Activity:    0,
				Experiment:  0,
				Application: APPLICATION,
			},
			&Enrichment{Verbosity: "lean", Cong: &Cong{Algorithm: "vegas"}},
			&Enrichment{Verbosity: "lean", Cong: &Cong{Algorithm: "vegas"}},
			false,
		},
	}

	for i, test := range tests {
		ff := NewFirefly(test.id, test.nl, test.ebpf)
		pl, err := ff.Payload(test.withSyslog)
		if err != nil {
			t.Errorf("error generating a payload [%d/%d]: %v", i, len(tests), err)
		}

		inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(pl))
		if err != nil {
			t.Errorf("error unmarshalling the payload [%d/%d]: %v", i, len(tests), err)
		}

		if err := sch.Validate(inst); err != nil {
			t.Errorf("error validating the firefly [%d/%d]: %v", i, len(tests), err)
		}
	}
}
