package settings

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/pcolladosoto/glowd/plugins/np"
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
	PIDPath        string        `json:"pidPath"`
	WorkDir        string        `json:"workDir"`
	DefaultBackend string        `json:"defaultBackend"`
	StunServers    []string      `json:"stunServers"`
	Plugins        []interface{} `json:"-"`
	Backends       []interface{} `json:"-"`
}

// We need a type alias to avoid infinite recursion!
// Otherwise the first call to json.Unmarshal within
// func (c *Config) UnmarshalJSON(data []byte) error
// will recurse indefinitely...
type AuxConfig Config

type genericConfs struct {
	Plugins  map[string]interface{}
	Backends map[string]interface{}
}

func (c *Config) UnmarshalJSON(data []byte) error {
	tmpConf := AuxConfig{}
	if err := json.Unmarshal(data, &tmpConf); err != nil {
		return fmt.Errorf("couldn't unmarshal into tmpConf: %w", err)
	}
	slog.Debug("unmarshalled tmpConf", "tmpConf", tmpConf)

	genericConf := genericConfs{}
	if err := json.Unmarshal(data, &genericConf); err != nil {
		return fmt.Errorf("couldn't unmarshal into genericConfs: %w", err)
	}
	slog.Debug("unmarshalled genericConf", "genericConf", genericConf)

	for k, v := range genericConf.Plugins {
		pluginConf, err := json.Marshal(v)
		if err != nil {
			return fmt.Errorf("couldn't marshall the plugin configuration for %q: %w", k, err)
		}
		switch strings.ToLower(k) {
		case "namedpipe":
			slog.Debug("got a namedPipe plugin", "v", v)
			npConf := np.NamedPipePluginConf{}
			if err := json.Unmarshal(pluginConf, &npConf); err != nil {
				return fmt.Errorf("couldn't unmarshal the named pipe: %w", err)
			}
			tmpConf.Plugins = append(tmpConf.Plugins, npConf)
		default:
			return fmt.Errorf("unknown plugin %q", k)
		}
	}

	// Propagate the configuration back
	*c = Config(tmpConf)

	return nil
}

func ReadConf(confFile string) (Config, error) {
	conf := Config{}
	content, err := os.ReadFile(confFile)
	if err != nil {
		return conf, err
	}

	if err := json.Unmarshal(content, &conf); err != nil {
		return conf, fmt.Errorf("couldn't unmarshal the configuration: %w", err)
	}

	return conf, nil
}
