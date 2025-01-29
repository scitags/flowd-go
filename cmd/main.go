package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	glowd "github.com/scitags/flowd-go"
	"github.com/scitags/flowd-go/backends/ebpf"
	"github.com/scitags/flowd-go/settings"
	glowdTypes "github.com/scitags/flowd-go/types"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&confPath, "conf", "/etc/glowd/conf.json", "path of the JSON configuration file")
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "info", "log level: one of debug, info, warn, error")
}

var (
	rootCmd = &cobra.Command{
		Use:   "glowd",
		Short: "A SciTags client.",
		Long:  "Go nuts!",

		// Note we need to configure logging here as flags are not parsed before
		// calling rootCmd.Execute on main... As this PreRun function is persistent,
		// it'll be inherited by subcommands
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			logLevel, ok := logLevelMap[logLevelFlag]
			if !ok {
				logLevel = slog.LevelInfo
			}

			logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
				AddSource: true,
				Level:     logLevel,
				ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
					// Remove time.
					if a.Key == slog.TimeKey && len(groups) == 0 {
						return slog.Attr{}
					}

					// Remove the directory from the source's filename.
					if a.Key == slog.SourceKey {
						source := a.Value.Any().(*slog.Source)
						source.File = filepath.Base(source.File)
					}

					// Format the flow tag as both a binary and hex number
					if a.Key == glowd.FlowTagKey {
						// When slog gobbles the flow tag it becomes a uint64 instead of a uint32
						// apparently...
						flowLabel, ok := a.Value.Any().(uint64)
						if ok {
							return slog.Attr{Key: a.Key, Value: slog.StringValue(fmt.Sprintf("%#x;(%#b)", flowLabel, flowLabel))}
						}
					}

					// Format the flow hashes
					if a.Key == glowd.FlowHashKey {
						flowHash, ok := a.Value.Any().(ebpf.FlowFourTuple)
						if ok {
							return slog.Attr{Key: a.Key, Value: slog.StringValue(
								fmt.Sprintf("%s(%#x|%#x);%d;%d", net.IP([]byte{
									byte(flowHash.IPv6Hi & (0xFF << 7) >> 7),
									byte(flowHash.IPv6Hi & (0xFF << 6) >> 6),
									byte(flowHash.IPv6Hi & (0xFF << 5) >> 5),
									byte(flowHash.IPv6Hi & (0xFF << 4) >> 4),
									byte(flowHash.IPv6Hi & (0xFF << 3) >> 3),
									byte(flowHash.IPv6Hi & (0xFF << 2) >> 2),
									byte(flowHash.IPv6Hi & (0xFF << 1) >> 1),
									byte(flowHash.IPv6Hi & 0xFF),
									byte(flowHash.IPv6Lo & (0xFF << 7) >> 7),
									byte(flowHash.IPv6Lo & (0xFF << 6) >> 6),
									byte(flowHash.IPv6Lo & (0xFF << 5) >> 5),
									byte(flowHash.IPv6Lo & (0xFF << 4) >> 4),
									byte(flowHash.IPv6Lo & (0xFF << 3) >> 3),
									byte(flowHash.IPv6Lo & (0xFF << 2) >> 2),
									byte(flowHash.IPv6Lo & (0xFF << 1) >> 1),
									byte(flowHash.IPv6Lo & 0xFF),
								}), flowHash.IPv6Hi, flowHash.IPv6Lo, flowHash.SrcPort, flowHash.DstPort),
							)}
						}
					}

					return a
				},
			}))
			slog.SetDefault(logger)
		},
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Get the built version.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("built commit: %s\nbase version: %s\n", builtCommit, baseVersion)
		},
	}

	confCmd = &cobra.Command{
		Use:   "conf",
		Short: "Dump the configuration we're running with.",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := settings.ReadConf(confPath)
			if err != nil {
				slog.Error("couldn't read the configuration", "err", err)
				return
			}
			jsonConf, err := json.MarshalIndent(conf, "", "    ")
			if err != nil {
				fmt.Printf("couldn't marshall the configuration: %v", err)
			}
			fmt.Printf("%s\n", jsonConf)
		},
	}

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "Time to show what glowd can do!",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := settings.ReadConf(confPath)
			if err != nil {
				slog.Error("couldn't read the configuration", "err", err)
				return
			}
			slog.Debug("read configuration", "conf", conf)

			if err := os.WriteFile(conf.General.PIDPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
				slog.Error("couldn't create the PID file", "path", conf.General.PIDPath, "err", err)
			}
			defer os.Remove(conf.General.PIDPath)

			if err := initPlugins(conf.Plugins); err != nil {
				slog.Error("couldn't initialise the plugins", "err", err)
				return
			}
			defer cleanupPlugins(conf.Plugins)

			if err := initBackends(conf.Backends); err != nil {
				slog.Error("couldn't initialise the backends", "err", err)
				return
			}
			defer cleanupBackends(conf.Backends)

			// Set up the necessary channels, one per plugin and per backend
			pluginChans := make([]chan glowdTypes.FlowID, 0, len(conf.Plugins))
			backendChans := make([]chan glowdTypes.FlowID, 0, len(conf.Backends))

			// Set up the broadcast channel for exiting cleanly
			doneChan := make(chan struct{})

			// Dispatch the producers (i.e. plugins)
			for i, plugin := range conf.Plugins {
				pluginChans = append(pluginChans, make(chan glowdTypes.FlowID))
				go plugin.Run(doneChan, pluginChans[i])
			}

			// Dispatch the consumers (i.e. backends)
			for i, backend := range conf.Backends {
				backendChans = append(backendChans, make(chan glowdTypes.FlowID))
				go backend.Run(doneChan, backendChans[i])
			}

			// Funnel plugin flowIDs into an aggregate channel.
			// Buffer the channel so that consumers (i.e. backends)
			// can have some wiggle room if under pressuer.
			agg := make(chan glowdTypes.FlowID)
			for i, ch := range pluginChans {
				go func(c chan glowdTypes.FlowID, i int) {
					slog.Debug("began listening for plugin flowIDs", "i", i)
					for flowID := range c {
						slog.Debug("funneling flowID", "i", i)
						agg <- flowID
					}
				}(ch, i)
			}

			// Set up the machinery for catching SIGINT (i.e. os.Interrupt) and SIGTERM
			// which will be sent by SystemD when stopping/restarting the service.
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

			// Simply listen for events on the aggregated channel and dispatch
			// them to the backends. Another option could be reflect.Select,
			// although it's much less performing... Could a point-to-point
			// (i.e. mesh) architecture be better?
			slog.Info("let's go!", "nPlugins", len(pluginChans), "nBackends", len(backendChans))
			for {
				select {
				case flowID, ok := <-agg:
					if !ok {
						slog.Warn("somebody closed the aggregated channel!")
						return
					}
					slog.Debug("dispatching flowID to backends")
					for _, ch := range backendChans {
						ch <- flowID
					}
				case <-sigChan:
					close(doneChan)
					return
				}
			}
		},
	}

	confPath     string
	logLevelFlag string
	builtCommit  string
	baseVersion  string

	logLevelMap = map[string]slog.Level{
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}
)

func init() {
	// Disable completion please!
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add the different sub-commands
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(confCmd)
	rootCmd.AddCommand(runCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
