package xrootd

import (
	"os"
	"strings"
	"testing"
)

const TEST_DIR = "./testdata"

func TestUnmarshalDetailMonit(t *testing.T) {
	entries, err := os.ReadDir(TEST_DIR)
	if err != nil {
		t.Fatalf("couldn't read %q...", TEST_DIR)
	}

	for _, f := range entries {
		if !strings.HasSuffix(f.Name(), ".bin") {
			continue
		}

		raw, err := os.ReadFile(TEST_DIR + "/" + f.Name())
		if err != nil {
			t.Errorf("error reading %q: %v\n", f.Name(), err)
			continue
		}

		msg, err := ParseDatagram(raw)
		if err != nil {
			t.Errorf("error unmarshaling: %v", err)
			continue
		}

		t.Logf("decoded:\n%+v\n", msg)
	}
}
