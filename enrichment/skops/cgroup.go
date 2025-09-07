//go:build linux

package skops

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/containerd/cgroups"
	"github.com/prometheus/procfs"
)

func GetCgroupInfo() (string, error) {
	if cgroups.Mode() != cgroups.Unified {
		return "", fmt.Errorf("running with cgroup mode %d, want %d", cgroups.Mode(), cgroups.Unified)
	}

	procPID := os.Getpid()
	proc, err := procfs.NewProc(procPID)
	if err != nil {
		return "", fmt.Errorf("error getting proc entry for PID %d: %w", procPID, err)
	}

	cgroups, err := proc.Cgroups()
	if err != nil {
		return "", fmt.Errorf("error getting cgroup information: %w", err)
	}

	for i, cgroup := range cgroups {
		slog.Debug("cgroup", "i", i, "cgroup", cgroup)
	}

	if len(cgroups) == 0 {
		return "", fmt.Errorf("the process belongs to no cgroups: we can't handle it")
	}

	if len(cgroups) > 1 {
		return "", fmt.Errorf("the process belongs to more than one cgroup: we can't handle it")
	}

	return cgroups[0].Path, nil
}
