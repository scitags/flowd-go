package fireflyp

import (
	"fmt"
	"os"
	"path"
	"testing"
)

func TestParseIncomingFirefly(t *testing.T) {
	hasSyslogHeader := map[string]bool{
		"start_firefly.firefly": false,
		"end_firefly.firefly":   false,
		"sample.firefly":        true,
	}

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

		firefly, err := parseFirefly(data, hasSyslogHeader[tf.Name()])
		if err != nil {
			t.Errorf("couldn't parse %q: %v", tfPath, err)
		}

		fmt.Printf("parsed firefly %q: %+v\n", tfPath, firefly)
	}
}
