//go:build linux && cgo

package ebpf

import (
	_ "embed"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	bpf "github.com/aquasecurity/libbpfgo"
)

//go:embed marker.bpf.c
var ebfpSrc []byte

func Launch() {
	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	defer bpfModule.Close()

	err = bpfModule.BPFLoadObject()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	hook := bpfModule.TcHookInit()
	defer func() {
		if err := hook.Destroy(); err != nil {
			fmt.Fprintln(os.Stderr, err)
		}
	}()

	err = hook.SetInterfaceByName("lo")
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to set tc hook on interface lo: %v", err)
		os.Exit(-1)
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

	bpfMap, err := bpfModule.GetMap("flowLabels")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}
	keyA := struct{x uint64; y uint64; z uint16; w uint16}{0, 1, 2, 3}
	keyAUnsafe := unsafe.Pointer(&keyA)
	val, err := bpfMap.GetValue(keyAUnsafe)
	if err != nil {
		fmt.Printf("error getting the map value: %v\n", err)
	}
	fmt.Printf("value: %+v\n", val)
}
