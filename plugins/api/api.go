package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/pcolladosoto/glowd"
)

var (
	configurationTags = map[string]bool{
		"bindaddress": false,
		"bindport":    false,
	}

	DefaultConf = ApiPluginConf{
		BindAddress: "127.0.0.1",
		BindPort:    7777,
	}
)

type ApiPluginConf struct {
	BindAddress string `json:"bindAddress"`
	BindPort    int    `json:"bindPort"`
}

// We need an alias to avoid infinite recursion
// in the unmarshalling logic
type AuxApiPluginConf ApiPluginConf

func (c *ApiPluginConf) UnmarshalJSON(data []byte) error {
	tmp := map[string]interface{}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmp map: %w", err)
	}

	for k := range tmp {
		delete(configurationTags, strings.ToLower(k))
	}

	tmpConf := AuxApiPluginConf{}
	if err := json.Unmarshal(data, &tmpConf); err != nil {
		return fmt.Errorf("couldn't unmarshall into tmpConf: %w", err)
	}

	for k := range configurationTags {
		switch strings.ToLower(k) {
		case "bindaddress":
			tmpConf.BindAddress = DefaultConf.BindAddress
		case "bindport":
			tmpConf.BindPort = DefaultConf.BindPort
		default:
			return fmt.Errorf("unknown configuration key %q", k)
		}
	}

	// Store the results!
	*c = ApiPluginConf(tmpConf)

	return nil
}

type ApiPlugin struct {
	server *echo.Echo

	conf ApiPluginConf
}

func New(conf *ApiPluginConf) *ApiPlugin {
	// Parenthesis required due to a parsing ambiguity!
	if conf == nil {
		return &ApiPlugin{conf: DefaultConf}
	}
	return &ApiPlugin{conf: *conf}
}

func (p *ApiPlugin) String() string {
	return "api"
}

func (p *ApiPlugin) Init() error {
	slog.Debug("initialising the api plugin")
	p.server = echo.New()

	// Configure the methods for each path
	p.server.GET("/", handleRoot)
	p.server.GET("/dummy/start", handleDummyStartFlow)
	p.server.GET("/dummy/end", handleDummyEndFlow)

	// Prevent the banner from showing up in the log
	p.server.HideBanner = true
	p.server.HidePort = true

	return nil
}

func (p *ApiPlugin) Run(done <-chan struct{}, outChan chan<- glowd.FlowID) {
	slog.Debug("running the api plugin")

	// Configure the middleware for extending the context of the
	// different handlers. We defer that to this point so that we
	// have a handle of the channel we are to push events into.
	p.server.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			return next(&extendedContext{c, p.server.Routes(), outChan})
		}
	})

	go func() {
		if err := p.server.Start(fmt.Sprintf("%s:%d", p.conf.BindAddress, p.conf.BindPort)); err != http.ErrServerClosed {
			slog.Error("couldn't start the API server", "err", err)
		}
	}()

	// Simply wait until we're done
	<-done
	slog.Debug("cleanly exiting the api plugin")
}

func (p *ApiPlugin) Cleanup() error {
	slog.Debug("cleaning up the api plugin")
	if err := p.server.Shutdown(context.TODO()); err != nil {
		return fmt.Errorf("error shutting down the API server: %w", err)
	}
	return nil
}
