package stun

// func TestGetExternalIp(t *testing.T) {
// 	tests := []struct {
// 		name string
// 		want net.IP
// 	}{
// 		{"wrong http scheme", net.ParseIP("192.168.1.1")},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			var pubIP net.IP
// 			var err error

// 			pubIP, err = GetPubIPOverSTUN(IPv4)
// 			if err != nil {
// 				t.Errorf("GetExternalIP(IPv4) errored out: %v", err)
// 			}
// 			fmt.Printf("discovered external IPv4: %s\n", pubIP)

// 			pubIP, err = GetPubIPOverSTUN(IPv6)
// 			if err != nil {
// 				t.Errorf("GetExternalIP(IPv6) errored out: %v", err)
// 			}
// 			fmt.Printf("discovered external IPv6: %s\n", pubIP)

// 			pubIP, err = GetDefaultOutboundIP(IPv4)
// 			if err != nil {
// 				t.Errorf("GetDefaultOutboundIP(IPv4) errored out: %v", err)
// 			}
// 			fmt.Printf("   discovered local IPv4: %s\n", pubIP)

// 			pubIP, err = GetDefaultOutboundIP(IPv6)
// 			if err != nil {
// 				t.Errorf("GetDefaultOutboundIP(IPv6) errored out: %v", err)
// 			}
// 			fmt.Printf("   discovered local IPv6: %s\n", pubIP)

// 			pubIP, err = GetPubIPOverHTTP()
// 			if err != nil {
// 				t.Errorf("GetPubIPOverHTTP() errored out: %v", err)
// 			}
// 			fmt.Printf("discovered external IPvx: %s\n", pubIP)

// 			// Just so we know what to do on other tests!
// 			// if err != nil || !net.IP.Equal(got, tt.want) {
// 			// 	t.Errorf("GetExternalIP = %v; wanted %v, err %v", got, tt.want, err)
// 			// }
// 		})
// 	}
// }
