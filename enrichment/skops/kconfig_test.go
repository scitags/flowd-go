//go:buid linux && ebpf

package skops

// Plundered from https://github.com/cilium/ebpf/tree/dc256170d8d343fbfdf751c54f4cbb4b4d7aaba3/internal/kconfig

import (
	"os"
	"strconv"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestKconfigParse(t *testing.T) {
	f, err := os.Open("testdata/test.kconfig")
	if err != nil {
		t.Fatal("Error reading /testdata/test.kconfig: ", err)
	}
	defer f.Close()

	config, err := Parse(f, nil)
	if err != nil {
		t.Fatal("Error parsing kconfig: ", err)
	}

	expected := map[string]string{
		"CONFIG_TRISTATE": "m",
		"CONFIG_BOOL":     "y",
		"CONFIG_CHAR":     "100",
		"CONFIG_USHORT":   "30000",
		"CONFIG_INT":      "123456",
		"CONFIG_ULONG":    "0xDEADBEEFC0DE",
		"CONFIG_STR":      `"abracad"`,
		"CONFIG_FOO":      `"foo"`,
	}
	if !cmp.Equal(config, expected) {
		t.Errorf("got %v; expected %v", config, expected)
	}

	filter := map[string]struct{}{"CONFIG_FOO": {}}
	config, err = Parse(f, filter)
	if err != nil {
		t.Fatal("Error parsing gzipped kconfig: ", err)
	}

	expected = map[string]string{"CONFIG_FOO": `"foo"`}
	if !cmp.Equal(config, expected) {
		t.Errorf("got %v; expected %v", config, expected)
	}
}

func TestKconfigFind(t *testing.T) {
	f, err := FindKConfig()
	if err != nil {
		t.Fatalf("error finding kernel's kconfig: %v", err)
	}
	f.Close()
}

func TestKconfigHz(t *testing.T) {
	f, err := FindKConfig()
	if err != nil {
		t.Fatalf("error finding kernel's kconfig: %v", err)
	}
	defer f.Close()

	config, err := Parse(f, map[string]struct{}{"CONFIG_HZ": {}})
	if err != nil {
		t.Errorf("couldn't parse kconfig: %v", err)
	}

	hz, ok := config["CONFIG_HZ"]
	if !ok {
		t.Errorf("couldn't find CONFIG_HZ")
	}

	_, err = strconv.ParseUint(hz, 10, 64)
	if err != nil {
		t.Errorf("error parsing HZ: %v", err)
	}
}
