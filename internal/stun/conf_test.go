package stun

import (
	"os"
	"testing"
)

func TestConf(t *testing.T) {
	entries, err := os.ReadDir("./testdata")
	if err != nil {
		t.Fatalf("error reading testdir: %v", err)
	}

	for _, entry := range entries {
		r, err := os.ReadFile("./testdata/" + entry.Name())
		if err != nil {
			t.Errorf("error reading %q: %v", entry.Name(), err)
			continue
		}

		c := Config{}

		if err := c.UnmarshalYAML(r); err != nil {
			t.Errorf("error unmarshaling %q: %v", entry.Name(), err)
		}

		t.Logf("%q: %v", entry.Name(), c)
	}
}
