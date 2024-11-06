package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/pcolladosoto/glowd"
	"github.com/pcolladosoto/glowd/settings"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.PersistentFlags().StringVar(&confPath, "conf", "/etc/glowd/conf.json", "path of the JSON configuration file")
	rootCmd.PersistentFlags().StringVar(&logLevelFlag, "log-level", "debug", "log level: one of debug, info, warn, error")
}

var (
	rootCmd = &cobra.Command{
		Use:   "glowd",
		Short: "A SciTags client.",
		Long:  "Go nuts!",
	}

	versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Get the built version.",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("built commit: %s\n", builtCommit)
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

			if err := os.WriteFile(conf.PIDPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0644); err != nil {
				slog.Error("couldn't create the PID file", "path", conf.PIDPath, "err", err)
			}
			defer os.Remove(conf.PIDPath)

			plugins, err := createPlugins(conf)
			if err != nil {
				slog.Error("couldn't create the plugins", "err", err)
				return
			}
			defer cleanupPlugins(plugins)

			backends, err := createBackends(conf)
			if err != nil {
				slog.Error("couldn't create the backends", "err", err)
				return
			}
			defer cleanupBackends(backends)

			// Set up the necessary channels, one per plugin and per backend
			pluginChans := make([]chan glowd.FlowID, 0, len(plugins))
			backendChans := make([]chan glowd.FlowID, 0, len(backends))

			// Set up the broadcast channel for exiting cleanly
			doneChan := make(chan struct{})

			// Dispatch the producers (i.e. plugins)
			for i, plugin := range plugins {
				pluginChans = append(pluginChans, make(chan glowd.FlowID))
				go plugin.Run(doneChan, pluginChans[i])
			}

			// Dispatch the consumers (i.e. backends)
			for i, backend := range backends {
				backendChans = append(backendChans, make(chan glowd.FlowID))
				go backend.Run(doneChan, backendChans[i])
			}

			// Funnel plugin flowIDs into an aggregate channel.
			// Buffer the channel so that consumers (i.e. backends)
			// can have some wiggle room if under pressuer.
			agg := make(chan glowd.FlowID)
			for i, ch := range pluginChans {
				go func(c chan glowd.FlowID, i int) {
					slog.Debug("began listening for plugin flowIDs", "i", i)
					for flowID := range c {
						slog.Debug("funneling flowID", "i", i)
						agg <- flowID
					}
				}(ch, i)
			}

			// Set up the machinery for catching SIGINT
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

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
	builtCommit  = "dev"

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
	rootCmd.AddCommand(runCmd)
}

func main() {
	logLevel, ok := logLevelMap[logLevelFlag]
	if !ok {
		logLevel = slog.LevelDebug
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
			return a
		},
	}))
	slog.SetDefault(logger)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
