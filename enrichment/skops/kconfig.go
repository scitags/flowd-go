//go:buid linux && ebpf

package skops

// Plundered from https://github.com/cilium/ebpf/tree/dc256170d8d343fbfdf751c54f4cbb4b4d7aaba3/internal/kconfig

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// Most (if not all) kernel's have a default HZ value of 1000.
// Instead of failing, just go with the default if we cannot
// load the kconfig or anything of the sort happens.
const DEFAULT_HZ uint64 = 1000

// KernelRelease returns the release string of the running kernel.
// Its format depends on the Linux distribution and corresponds to directory
// names in /lib/modules by convention. Some examples are 5.15.17-1-lts and
// 4.19.0-16-amd64.
func KernelRelease() (string, error) {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "", fmt.Errorf("uname failed: %w", err)
	}

	return unix.ByteSliceToString(uname.Release[:]), nil
}

// FindKConfig searches for a kconfig file on the host.
//
// It first reads from /boot/config- of the current running kernel and tries
// /proc/config.gz if nothing was found in /boot.
// If none of the file provide a kconfig, it returns an error.
func FindKConfig() (*os.File, error) {
	kernelRelease, err := KernelRelease()
	if err != nil {
		return nil, fmt.Errorf("cannot get kernel release: %w", err)
	}

	path := "/boot/config-" + kernelRelease
	f, err := os.Open(path)
	if err == nil {
		return f, nil
	}

	f, err = os.Open("/proc/config.gz")
	if err == nil {
		return f, nil
	}

	return nil, fmt.Errorf("neither %s nor /proc/config.gz provide a kconfig", path)
}

// Parse parses the kconfig file for which a reader is given.
// All the CONFIG_* which are in filter and which are set set will be
// put in the returned map as key with their corresponding value as map value.
// If filter is nil, no filtering will occur.
// If the kconfig file is not valid, error will be returned.
func Parse(source io.ReaderAt, filter map[string]struct{}) (map[string]string, error) {
	var r io.Reader
	zr, err := gzip.NewReader(io.NewSectionReader(source, 0, math.MaxInt64))
	if err != nil {
		r = io.NewSectionReader(source, 0, math.MaxInt64)
	} else {
		// Source is gzip compressed, transparently decompress.
		r = zr
	}

	ret := make(map[string]string, len(filter))

	s := bufio.NewScanner(r)

	for s.Scan() {
		line := s.Bytes()
		err = processKconfigLine(line, ret, filter)
		if err != nil {
			return nil, fmt.Errorf("cannot parse line: %w", err)
		}

		if filter != nil && len(ret) == len(filter) {
			break
		}
	}

	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("cannot parse: %w", err)
	}

	if zr != nil {
		return ret, zr.Close()
	}

	return ret, nil
}

// Golang translation of libbpf bpf_object__process_kconfig_line():
// https://github.com/libbpf/libbpf/blob/fbd60dbff51c870f5e80a17c4f2fd639eb80af90/src/libbpf.c#L1874
// It does the same checks but does not put the data inside the BPF map.
func processKconfigLine(line []byte, m map[string]string, filter map[string]struct{}) error {
	// Ignore empty lines and "# CONFIG_* is not set".
	if !bytes.HasPrefix(line, []byte("CONFIG_")) {
		return nil
	}

	key, value, found := bytes.Cut(line, []byte{'='})
	if !found {
		return fmt.Errorf("line %q does not contain separator '='", line)
	}

	if len(value) == 0 {
		return fmt.Errorf("line %q has no value", line)
	}

	if filter != nil {
		// NB: map[string(key)] gets special optimisation help from the compiler
		// and doesn't allocate. Don't turn this into a variable.
		_, ok := filter[string(key)]
		if !ok {
			return nil
		}
	}

	// This can seem odd, but libbpf only sets the value the first time the key is
	// met:
	// https://github.com/torvalds/linux/blob/0d85b27b0cc6/tools/lib/bpf/libbpf.c#L1906-L1908
	_, ok := m[string(key)]
	if !ok {
		m[string(key)] = string(value)
	}

	return nil
}

func getConfigHz() uint64 {
	f, err := FindKConfig()
	if err != nil {
		slog.Warn("error finding kernel's kconfig, using DEFAULT_HZ", "err", err)
		return DEFAULT_HZ
	}
	defer f.Close()

	config, err := Parse(f, map[string]struct{}{"CONFIG_HZ": {}})
	if err != nil {
		slog.Warn("couldn't parse kconfig, using DEFAULT_HZ", "err", err)
		return DEFAULT_HZ
	}

	hz, ok := config["CONFIG_HZ"]
	if !ok {
		slog.Warn("couldn't find CONFIG_HZ, using DEFAULT_HZ")
		return DEFAULT_HZ
	}

	hzp, err := strconv.ParseUint(hz, 10, 64)
	if err != nil {
		slog.Warn("couldn't parse CONFIG_HZ, using DEFAULT_HZ", "err", err, "hz", hz)
		return DEFAULT_HZ
	}

	return hzp
}
