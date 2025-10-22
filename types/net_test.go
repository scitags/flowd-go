package types

import (
	"net"
	"testing"
)

func TestIsIPv4(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"127.0.0.1", true},
		{"::1", false},
		{"2001:4860:4860::8844", false},
		{"192.168.1.1", true},
		{"::FFFF:192.168.0.1", true},
	}

	for _, test := range tests {
		ip := net.ParseIP(test.in)
		if ip == nil {
			t.Errorf("error parsing addr %q", test.in)
			continue
		}
		if is4 := IsIPv4(ip); is4 != test.want {
			t.Errorf("%q: got %v, want %v", test.in, is4, test.want)
		}
	}
}
