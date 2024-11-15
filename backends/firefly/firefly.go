package firefly

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"
	"time"

	glowd "github.com/scitags/flowd-go"
)

const (
	FIREFLY_VERSION int    = 1
	APPLICATION     string = "flowd-go v1.0.0"

	// Let's replicate 2024-11-02T16:07:01.769470+00:00.
	TIME_FORMAT string = "2006-01-02T15:04:05.999999-07:00"

	SYSLOG_FACILITY_LOCAL0        int    = 16
	SYSLOG_SEVERITY_INFORMATIONAL int    = 6
	SYSLOG_PRIORITY               int    = (SYSLOG_FACILITY_LOCAL0 << 3) | SYSLOG_SEVERITY_INFORMATIONAL
	SYSLOG_VERSION                int    = 1
	SYSLOG_APP_NAME               string = "flowd-go"
	SYSLOG_PROC_ID                string = "-"
	SYSLOG_MSG_ID                 string = "firefly-json"
	SYSLOG_STRUCT_DATA            string = "-"
)

var (
	SYSLOG_HEADER string
)

func init() {
	hostName, err := os.Hostname()
	if err != nil {
		hostName = "no idea!"
	}

	SYSLOG_HEADER = fmt.Sprintf("<%d>%d %%s %s %s %s %s %s ",
		SYSLOG_PRIORITY, SYSLOG_VERSION, hostName,
		SYSLOG_APP_NAME, SYSLOG_PROC_ID, SYSLOG_MSG_ID,
		SYSLOG_STRUCT_DATA,
	)
}

type firefly struct {
	Version       int `json:"version"`
	FlowLifecycle struct {
		State       string `json:"state"`
		CurrentTime string `json:"current-time"`
		StartTime   string `json:"start-time"`
		EndTime     string `json:"end-time"`
	} `json:"flow-lifecycle"`
	FlowID struct {
		AFI      string `json:"afi"`
		SrcIP    string `json:"src-ip"`
		DstIP    string `json:"dst-ip"`
		Protocol string `json:"protocol"`
		SrcPort  uint16 `json:"src-port"`
		DstPort  uint16 `json:"dst-port"`
	} `json:"flow-id"`
	Context struct {
		ExperimentID uint32 `json:"experiment-id"`
		ActivityID   uint32 `json:"activity-id"`
		Application  string `json:"application"`
	} `json:"context"`
}

var (
	configurationTags = map[string]bool{
		"fireflydestinationport": false,
		"prependsyslog":          false,
	}

	DefaultConf = FireflyBackendConf{
		FireflyDestinationPort: 10514,
		PrependSyslog:          false,
	}
)

type FireflyBackendConf struct {
	FireflyDestinationPort uint16 `json:"fireflyDestinationPort"`
	PrependSyslog          bool   `json:"prependSyslog"`
}

// We need an alias to avoid infinite recursion
// in the unmarshalling logic
type AuxFireflyBackendConf FireflyBackendConf

type FireflyBackend struct {
	conf FireflyBackendConf
}

func (c *FireflyBackendConf) UnmarshalJSON(data []byte) error {
	tmp := map[string]interface{}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmp map: %w", err)
	}

	for k := range tmp {
		delete(configurationTags, strings.ToLower(k))
	}

	tmpConf := AuxFireflyBackendConf{}
	if err := json.Unmarshal(data, &tmpConf); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmpConf: %w", err)
	}

	for k := range configurationTags {
		switch strings.ToLower(k) {
		case "fireflydestinationport":
			tmpConf.FireflyDestinationPort = DefaultConf.FireflyDestinationPort
		case "prependsyslog":
			tmpConf.PrependSyslog = DefaultConf.PrependSyslog
		default:
			return fmt.Errorf("unknown configuration key %q", k)
		}
	}

	// Store the results!
	*c = FireflyBackendConf(tmpConf)

	return nil
}

func New(conf *FireflyBackendConf) *FireflyBackend {
	if conf == nil {
		return &FireflyBackend{conf: DefaultConf}
	}
	return &FireflyBackend{conf: *conf}
}

func (b *FireflyBackend) sendFirefly(flowID glowd.FlowID) error {
	dialNet := "udp6"
	if !strings.Contains(flowID.Dst.IP.String(), ":") {
		dialNet = "udp4"
	}
	conn, err := net.Dial(dialNet, fmt.Sprintf("%s:%d", flowID.Dst.IP, b.conf.FireflyDestinationPort))
	if err != nil {
		return fmt.Errorf("couldn't initialize UDP socket: %w", err)
	}
	defer func() {
		if err := conn.Close(); err != nil {
			slog.Warn("error closing UDP socket", "err", err)
		}
	}()

	var localFirefly firefly
	localFirefly.Version = FIREFLY_VERSION
	localFirefly.FlowLifecycle.State = flowID.State.String()
	localFirefly.FlowLifecycle.CurrentTime = time.Now().UTC().Format(TIME_FORMAT)
	localFirefly.FlowID.AFI = fmt.Sprintf("ipv%s", string(dialNet[len(dialNet)-1]))
	localFirefly.FlowID.SrcIP = flowID.Src.IP.String()
	localFirefly.FlowID.DstIP = flowID.Dst.IP.String()
	localFirefly.FlowID.Protocol = flowID.Protocol.String()
	localFirefly.FlowID.SrcPort = flowID.Src.Port
	localFirefly.FlowID.DstPort = flowID.Dst.Port
	localFirefly.Context.ExperimentID = flowID.Experiment
	localFirefly.Context.ActivityID = flowID.Activity
	localFirefly.Context.Application = APPLICATION

	if flowID.State == glowd.START {
		localFirefly.FlowLifecycle.StartTime = flowID.StartTs.Format(TIME_FORMAT)
	} else if flowID.State == glowd.END {
		localFirefly.FlowLifecycle.StartTime = flowID.StartTs.Format(TIME_FORMAT)
		localFirefly.FlowLifecycle.EndTime = flowID.EndTs.Format(TIME_FORMAT)
	} else {
		slog.Warn("got a flow with a wrong state", "flowID.State", flowID.State.String())
	}

	payload, err := json.Marshal(localFirefly)
	if err != nil {
		return fmt.Errorf("error marshalling firefly: %w", err)
	}

	if b.conf.PrependSyslog {
		syslogHeader := []byte(fmt.Sprintf(SYSLOG_HEADER, localFirefly.FlowLifecycle.CurrentTime))
		payload = append(syslogHeader, payload...)
	}

	slog.Debug("sending firefly", "dst", flowID.Dst.IP)
	_, err = conn.Write(payload)
	if err != nil {
		return fmt.Errorf("couldn't send the firefly: %w", err)
	}

	return nil
}

// Just implement the glowd.Backend interface
func (b *FireflyBackend) Init() error {
	slog.Debug("initialising the firefly backend")
	return nil
}

func (b *FireflyBackend) Run(done <-chan struct{}, inChan <-chan glowd.FlowID) {
	slog.Debug("running the firefly backend")
	for {
		select {
		case flowID, ok := <-inChan:
			if !ok {
				slog.Warn("somebody closed the input channel!")
				return
			}
			slog.Debug("got a flowID")
			if err := b.sendFirefly(flowID); err != nil {
				slog.Error("error sending the firefly", "err", err)
			}
		case <-done:
			slog.Debug("cleanly exiting the firefly backend")
			return
		}
	}
}

func (b *FireflyBackend) Cleanup() error {
	slog.Debug("cleaning up the firefly backend")
	return nil
}
