//go:build darwin || !cgo

package ebpf

import "github.com/pcolladosoto/glowd"

// Just implement the glowd.Backend interface
func Init() error                              { return nil }
func Run(<-chan struct{}, <-chan glowd.FlowID) {}
func Cleanup() error                           { return nil }
