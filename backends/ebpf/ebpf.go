//go:build linux && cgo

package ebpf

import (
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
	"github.com/pcolladosoto/glowd"
)

const TARGET_IFACE string = "lo"

var (
	//go:embed marker.bpf.o
	bpfObj []byte

	bpfModule *bpf.Module
	hook      *bpf.TcHook
)

func Cleanup() error {
	if err := hook.Destroy(); err != nil {
		slog.Warn("error destroying the hook", "err", err)
	}
	bpfModule.Close()

	return nil
}

func Init() error {
	// bpfModule, err := bpf.NewModuleFromBuffer(bpfObj, "marker")

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		return fmt.Errorf("error creating the BPF module: %w", err)
	}

	err = bpfModule.BPFLoadObject()
	if err != nil {
		return fmt.Errorf("error loading the BPF object: %w", err)
	}

	hook := bpfModule.TcHookInit()
	err = hook.SetInterfaceByName(TARGET_IFACE)
	if err != nil {
		return fmt.Errorf("failed to set TC hook on interface %s: %w", TARGET_IFACE, err)
	}

	hook.SetAttachPoint(bpf.BPFTcEgress)
	err = hook.Create()
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok && errno != syscall.EEXIST {
			fmt.Fprintln(os.Stderr, "tc hook create: %v", err)
		}
	}

	tcProg, err := bpfModule.GetProgram("target")
	if tcProg == nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	var tcOpts bpf.TcOpts // https://elixir.bootlin.com/linux/v6.8.4/source/tools/testing/selftests/bpf/prog_tests/tc_bpf.c#L26
	tcOpts.ProgFd = int(tcProg.GetFd())
	tcOpts.Handle = 1
	tcOpts.Priority = 1
	err = hook.Attach(&tcOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	// test for query
	tcOpts.ProgFd = 0
	tcOpts.ProgId = 0
	err = hook.Query(&tcOpts)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	if tcOpts.Handle != 1 {
		fmt.Fprintln(os.Stderr, "query info error, handle:%d", tcOpts.Handle)
		os.Exit(-1)
	}

	// test for detach
	defer func() {
		tcOpts.ProgFd = 0
		tcOpts.ProgId = 0
		err = hook.Detach(&tcOpts)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(-1)
		}
	}()

}

func Run(<-chan glowd.FlowID) {
	bpfMap, err := bpfModule.GetMap("flowLabels")
	if err != nil {
		return fmt.Errorf("error getting the BPF map: %w", err)
	}

	keyA := struct {
		x uint64
		y uint64
		z uint16
		w uint16
	}{0, 1, 2, 3}
	keyAUnsafe := unsafe.Pointer(&keyA)
	val, err := bpfMap.GetValue(keyAUnsafe)
	if err != nil {
		slog.Warn("error getting the map value", "err", err)
	}
	slog.Debug("retrieved value from map", "key", keyA, "val", val)
}
