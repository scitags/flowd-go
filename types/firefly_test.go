package types

import (
	"os"
	"path"
	"testing"
)

func TestParseIncomingFirefly(t *testing.T) {
	testFiles, err := os.ReadDir("testdata")
	if err != nil {
		t.Errorf("couldn't list the testdata directory: %v", err)
	}

	for _, tf := range testFiles {
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
