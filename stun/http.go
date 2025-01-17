package stun

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
)

// The serviceURLs map contains the URLs where HTTP-based discovery services can be
// contacted together with the JSON key where the public IP is expected to be found.
var serviceURLs = map[string]string{
	"https://ipconfig.io/json":            "ip",
	"https://api64.ipify.org?format=json": "ip",
	// "http://ip-api.com/json/":          "query", // ip-api only provides IPv4 discovery!
}

// GetPubIPOverHTTP leverages HTTP-based services allowing us to retrieve our public IPv4 or IPv6
// address. Its implementation respects the IP version preferences configured in the OS. That usually
// translates to trying IPv6 before IPv4, but your mileage may vary depending on your OS' network stack
// configuration. The implementation currently supports the following Ip discovery services:
//   - ipconfig.io
//   - ipify.org
func GetPubIPOverHTTP() (net.IP, error) {
	// Let's try every endpoint until one works!
	for url, key := range serviceURLs {
		slog.Debug("trying to get public IP over HTTP", "url", url)

		rawIP, err := doRequest(url, key)
		if err != nil {
			slog.Warn("error getting the raw public IP", "err", err)
			continue
		}

		pIP, err := parseRawIP(rawIP)
		if err != nil {
			slog.Warn("couldn't parse the raw IP...")
			continue
		}

		return pIP, nil
	}
	return nil, fmt.Errorf("couldn't get public IP address and we exhausted URLs")
}

// Function doRequest simply carries out an HTTP request to an IP discovery service to then
// extract the public IP from the returned payload as a string.
func doRequest(url, key string) (string, error) {
	req, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return "", err
	}

	rawPayload := map[string]interface{}{}
	if err := json.Unmarshal(body, &rawPayload); err != nil {
		return "", fmt.Errorf("error unmarshaling the payload: %w", err)
	}

	rawIP, ok := rawPayload[key]
	if !ok {
		return "", fmt.Errorf("key %q not found in rawPayload", key)
	}

	ipStr, ok := rawIP.(string)
	if !ok {
		return "", fmt.Errorf("raw IP %v could't be cast to a string", rawIP)
	}

	return ipStr, nil
}

// Function parseRawIP simply wraps the parsing of IPvX addresses from strings with
// the appropriate error handling.
func parseRawIP(rawIP string) (net.IP, error) {
	pIP := net.ParseIP(rawIP)
	if pIP == nil {
		return pIP, fmt.Errorf("couldn't parse the raw IP %q", rawIP)
	}
	return pIP, nil
}
