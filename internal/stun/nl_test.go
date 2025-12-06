package stun

import (
	"testing"
)

func TestNlGetDefaultInterface(t *testing.T) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Errorf("error getting the default interface: %v", err)
	}
	t.Logf("default interface; name: %s, index: %d", i.Name, i.Index)
}

func TestNlGetInterfaceAddresses(t *testing.T) {
	i, err := GetDefaultInterface()
	if err != nil {
		t.Errorf("error getting the default interface: %v", err)
	}
	t.Logf("default interface; name: %s, index: %d", i.Name, i.Index)

	ip4, ip6, err := GetInterfacePrefixes(i)
	if err != nil {
		t.Errorf("error getting the interface addresses: %v", err)
	}
	t.Logf("interface addresses; ip4: %+v, ip6: %+v", ip4, ip6)
}
