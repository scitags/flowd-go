package stun

import "testing"

func TestPubGetPublicAddresses(t *testing.T) {
	pubIPs, err := GetPublicAddresses(Config{})
	if err != nil {
		t.Errorf("error getting the public IPs: %v", err)
	}
	t.Logf("pubIPs: %+v", pubIPs)
}
