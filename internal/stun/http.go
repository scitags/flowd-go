package stun

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"

	"golang.org/x/sys/unix"
)

// The serviceURLs map contains the URLs where HTTP-based discovery services can be
// contacted together with the JSON key where the public IP is expected to be found.
var serviceURLs = map[string]string{
	"https://api64.ipify.org?format=json": "ip",
	"https://ipconfig.io/json":            "ip",
	// "http://ip-api.com/json/":          "query", // ip-api only provides IPv4 discovery!
}

// GetPubIPOverHTTP leverages HTTP-based services allowing us to retrieve our public IPv4 or IPv6
// address. Its implementation respects the IP version preferences configured in the OS. That usually
// translates to trying IPv6 before IPv4, but your mileage may vary depending on your OS' network stack
// configuration. The implementation currently supports the following Ip discovery services:
//   - ipify.org
//   - ipconfig.io
func GetPubIPOverHTTP(c Config, family int, localAddr netip.Addr) (netip.Addr, error) {
	// Force HTTP requests to be made through the default interface
	var (
		addr *net.TCPAddr
		err  error
	)
	switch family {
	case unix.AF_INET:
		addr, err = net.ResolveTCPAddr("tcp4", localAddr.String()+":0")
	case unix.AF_INET6:
		addr, err = net.ResolveTCPAddr("tcp6", fmt.Sprintf("[%s]:0", localAddr.String()))
	default:
		return netip.Addr{}, fmt.Errorf("wrong family specified")
	}
	if err != nil {
		return netip.Addr{}, fmt.Errorf("couldn't resolve the local TCP address: %w", err)
	}
	dialer := &net.Dialer{LocalAddr: addr}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := dialer.Dial(network, addr)
		return conn, err
	}}
	client := &http.Client{Transport: transport}

	// Let's try every endpoint until one works!
	for url, key := range serviceURLs {
		slog.Debug("trying to get public IP over HTTP", "url", url)

		pIP, err := doRequest(client, url, key)
		if err != nil {
			slog.Warn("error getting the raw public IP", "err", err)
			continue
		}

		return pIP, nil
	}
	return netip.Addr{}, fmt.Errorf("couldn't get public IP address and we exhausted URLs")
}

// Function doRequest simply carries out an HTTP request to an IP discovery service to then
// extract the public IP from the returned payload as a string.
func doRequest(client *http.Client, url, key string) (netip.Addr, error) {
	req, err := client.Get(url)
	if err != nil {
		return netip.Addr{}, err
	}
	defer req.Body.Close()

	body, err := io.ReadAll(req.Body)
	if err != nil {
		return netip.Addr{}, err
	}

	rawPayload := map[string]interface{}{}
	if err := json.Unmarshal(body, &rawPayload); err != nil {
		return netip.Addr{}, fmt.Errorf("error unmarshaling the payload: %w", err)
	}

	rawIP, ok := rawPayload[key]
	if !ok {
		return netip.Addr{}, fmt.Errorf("key %q not found in rawPayload", key)
	}

	ipStr, ok := rawIP.(string)
	if !ok {
		return netip.Addr{}, fmt.Errorf("raw IP %v could't be cast to a string", rawIP)
	}

	pIP, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("couldn't parse the raw IP %q", rawIP)
	}

	return pIP, nil
}
