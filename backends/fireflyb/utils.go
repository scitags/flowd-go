package fireflyb

import (
	"fmt"
	"net"
	"strings"
)

// Function parseCollectorAddress handles the specified collector address
// and provides an address suitable for net.Dial.
func parseCollectorAddress(rawAddress string, port int) string {
	// This address format is suitable both for hostnames and raw IPv4 addresses.
	addressFmt := "%s:%d"

	// If we got an IPv6 address...
	if pIP := net.ParseIP(rawAddress); pIP != nil && strings.Contains(rawAddress, ":") {
		addressFmt = "[%s]:%d"
	}

	return fmt.Sprintf(addressFmt, rawAddress, port)
}
