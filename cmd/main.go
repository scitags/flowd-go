package main

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/pcolladosoto/glowd"
	"github.com/pcolladosoto/glowd/backends/ebpf"
	"github.com/pcolladosoto/glowd/plugins/np"
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

	ebpfTest = &cobra.Command{
		Use:   "ebpf-test",
		Short: "Try to load the eBPF program.",
		Run: func(cmd *cobra.Command, args []string) {
			ebpfBackend := ebpf.New(nil)
			if err := ebpfBackend.Init(); err != nil {
				fmt.Printf("error on Init(): %v\n", err)
				return
			}

			ebpfBackend.Run(nil, nil)

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)
			<-sigChan
			// time.Sleep(5 * time.Second)

			if err := ebpfBackend.Cleanup(); err != nil {
				fmt.Printf("error on Cleanup(): %v\n", err)
				return
			}
		},
	}

	npTest = &cobra.Command{
		Use:   "np-test",
		Short: "Try to create and read from a named pipe.",
		Run: func(cmd *cobra.Command, args []string) {
			namedPipe := np.New(nil)
			if err := namedPipe.Init(); err != nil {
				fmt.Printf("error setting up the named pipe: %v\n", err)
				return
			}
			defer func() {
				if err := namedPipe.Cleanup(); err != nil {
					fmt.Printf("error cleaning up the named pipe: %v\n", err)
				}
			}()

			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt)

			flowChan := make(chan glowd.FlowID)
			doneChan := make(chan struct{})
			go namedPipe.Run(doneChan, flowChan)

			ebpfBackend := ebpf.New(nil)
			if err := ebpfBackend.Init(); err != nil {
				fmt.Printf("error on Init(): %v\n", err)
				return
			}

			defer func() {
				if err := ebpfBackend.Cleanup(); err != nil {
					fmt.Printf("error cleaning up the ebpf backend: %v\n", err)
					return
				}
			}()

			go ebpfBackend.Run(doneChan, flowChan)

			// fireflyBackend := firefly.New()
			// go fireflyBackend.Run(doneChan, flowChan)

			// Block until we are told to quit
			<-sigChan
			close(doneChan)
		},
	}

	confTest = &cobra.Command{
		Use:   "conf-test",
		Short: "Try to get configuration to work.",
		Run: func(cmd *cobra.Command, args []string) {
			conf, err := settings.ReadConf(confPath)
			if err != nil {
				slog.Error("couldn't read the configuration", "err", err)
				return
			}
			slog.Debug("read configuration", "conf", conf)

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
	rootCmd.AddCommand(ebpfTest)
	rootCmd.AddCommand(npTest)
	rootCmd.AddCommand(confTest)
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
