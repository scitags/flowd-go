package glowd

import (
	"fmt"
	"net"
	"testing"
)

func TestGetExternalIp(t *testing.T) {
	tests := []struct {
		name string
		want net.IP
	}{
		{"wrong http scheme", net.ParseIP("192.168.1.1")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extIPv4, err := GetExternalIP(IPv4)
			if err != nil {
				t.Errorf("GetExternalIP(IPv4) errored out: %v", err)
			}
			fmt.Printf("discovered external IPv4: %s\n", extIPv4)

			extIPv6, err := GetExternalIP(IPv6)
			if err != nil {
				t.Errorf("GetExternalIP(IPv6) errored out: %v", err)
			}
			fmt.Printf("discovered external IPv6: %s\n", extIPv6)

			locIPv4, err := GetDefaultOutboundIP(IPv4)
			if err != nil {
				t.Errorf("GetDefaultOutboundIP(IPv4) errored out: %v", err)
			}
			fmt.Printf("   discovered local IPv4: %s\n", locIPv4)

			locIPv6, err := GetDefaultOutboundIP(IPv6)
			if err != nil {
				t.Errorf("GetDefaultOutboundIP(IPv6) errored out: %v", err)
			}
			fmt.Printf("   discovered local IPv6: %s\n", locIPv6)

			// Just so we know what to do on other tests!
			// if err != nil || !net.IP.Equal(got, tt.want) {
			// 	t.Errorf("GetExternalIP = %v; wanted %v, err %v", got, tt.want, err)
			// }
		})
	}
}
