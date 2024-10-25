package glowd

import (
	"encoding/json"
	"os"
)

// Sample config ripped from flowd
// CONFIG_PATH = '/etc/flowd/flowd.cfg'
// PID_FILE = '/var/run/flowd.pid'
// WORK_DIR = '/var/cache/flowd'
// DEFAULT_BACKEND = 'udp_firefly'
// NP_API_FILE = '/var/run/flowd'
// UDP_FIREFLY_PORT = 10514
// IP4_DISCOVERY = ('10.255.255.255', 1)
// IP6_DISCOVERY = ('fc00::', 1)
// STUN_SERVERS = [('stun.l.google.com', 19305), ('stun.services.mozilla.org', 3478)]
// NETSTAT_TIMEOUT = 2
// FIREFLY_LISTENER_HOST = "0.0.0.0"
// FIREFLY_LISTENER_PORT = 10514
// NETLINK_TIMEOUT = 2
// PROMETHEUS_SRV_PORT = 9000
// SS_PATH = '/usr/sbin/ss'

type Config struct {
	PIDPath        string
	WorkDir        string
	DefaultBackend string
	PipePath       string
	StunServers    []string
}

func ReadConf(confFile string) (Config, error) {
	content, err := os.ReadFile(confFile)
	if err != nil {
		return Config{}, err
	}

	var conf Config

	if err := json.Unmarshal(content, &conf); err != nil {
		return Config{}, err
	}

	return conf, nil
}
