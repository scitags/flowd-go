package netlink

import (
	"github.com/goccy/go-yaml"
	"github.com/scitags/flowd-go/types"
	"golang.org/x/sys/unix"
)

type Config struct {
	Protocol      uint8  `yaml:"protocol"`
	Ext           uint8  `yaml:"ext"`
	State         uint32 `yaml:"state"`
	CacheCapacity int    `yaml:"-"`
	Period        int    `yaml:"-"`
}

var DefaultConfig = Config{
	Protocol: unix.IPPROTO_TCP,
	Ext: 1<<(INET_DIAG_MEMINFO-1) |
		1<<(INET_DIAG_INFO-1) |
		1<<(INET_DIAG_VEGASINFO-1) |
		1<<(INET_DIAG_CONG-1) |
		1<<(INET_DIAG_TOS-1) |
		1<<(INET_DIAG_TCLASS-1) |
		1<<(INET_DIAG_SKMEMINFO-1) |
		1<<(INET_DIAG_SHUTDOWN-1),
	State:         types.TCP_ALL_FLAGS & ^(1 << uint(types.TCP_LISTEN)),
	CacheCapacity: 10,
	Period:        1000,
}

func (c *Config) UnmarshalYAML(b []byte) error {
	// Needed to break recursive calls into UnmarshalYAML
	type config Config

	def := config(DefaultConfig)

	if err := yaml.Unmarshal(b, &def); err != nil {
		return err
	}

	*c = Config(def)

	return nil
}
