package fireflyb

import (
	"os"
	"strings"
	"testing"
)

func TestConf(t *testing.T) {
	dir, err := os.ReadDir("./testdata")
	if err != nil {
		t.Fatalf("couldn't read testdata directory: %v", err)
	}

	for _, e := range dir {
		if !strings.HasSuffix(e.Name(), ".yml") {
			continue
		}

		r, err := os.ReadFile("./testdata/" + e.Name())
		if err != nil {
			t.Errorf("error reading configuration file %q: %v", e.Name(), err)
			continue
		}

		c := Config{}
		if err := c.UnmarshalYAML(r); err != nil {
			t.Errorf("error unmarshaling %q: %v", e.Name(), err)
			continue
		}
		t.Logf("%q: %v", e.Name(), c)
	}
}
