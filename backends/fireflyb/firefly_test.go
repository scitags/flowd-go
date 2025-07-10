package fireflyb

import (
	"fmt"
	"testing"
)

func TestParseCollectorAddress(t *testing.T) {
	port := 1234

	tests := []struct {
		in   string
		want string
	}{
		{"0.0.0.0", fmt.Sprintf("0.0.0.0:%d", port)},
		{"127.0.0.1", fmt.Sprintf("127.0.0.1:%d", port)},
		{"example.net", fmt.Sprintf("example.net:%d", port)},
		{"example.org", fmt.Sprintf("example.org:%d", port)},
		{"::1", fmt.Sprintf("[::1]:%d", port)},
		{"fe80::3333:2222:1111:0000", fmt.Sprintf("[fe80::3333:2222:1111:0000]:%d", port)},
	}

	for _, test := range tests {
		if got := parseCollectorAddress(test.in, port); got != test.want {
			t.Errorf("got %s != %s", got, test.want)
		}
	}
}
