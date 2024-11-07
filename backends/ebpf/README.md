# eBPF backend
This backend will set the IPv6 flow label in response to *flow events*. This implies this backend is only applicable for
IPv6-based traffic flows which, given the WLCG's prospects, should be a reality sooner rather than later in the context
of HEP. The backed is implemented as an eBPF program adhering to the CO:RE principles so that it's portable even across
kernel versions and there no need to recompile it when the program starts.

The flow label is derived from the flow event's experiment and activity IDs and 5 random bits to fill up the 20 bits comprising
the flow label. Be sure to check [Wikipedia](https://en.wikipedia.org/wiki/IPv6) for more information on the structure of an
IPv6 header.

Please note the eBPF backend is just a stub when targetting operating systems other than Linux, namely darwin (i.e. macOS).

On section [**Taming eBPF**](#taming-ebpf) you can find much more detailed and involved technical documentation regarding
the eBPF technology which can be a bit complex... Be sure to check the eBPF program's source on `marker.bpf.c` as it's
littered with informative comments providing context for cryptic lines and concepts.

## Configuration
Please refer to the Markdown-formatted documentation at the repository's root for more information on available
options. The following replicates the default configuration:

```json
{
    "backends": {
        "ebpf": {
            "targetInterface": "lo",
            "removeQdisc": true,
            "programPath": ""
        }
    }
}
```

## Taming eBPF
Our objective is simply getting an eBPF program to compile so that it can be deployed 'everywhere', simple as that!

Now, the reality is a bit more complex than one would think! Long story short, we've settled on leveraging the
rather new *Compile-Once Run-Everywhere* (CO:RE) methodology to accomplish just that.

### TL:DR
We have distilled the information below into a `Makefile` automating the process of building the eBPF program. One
can now simply run:

    $ make

And the compiled eBPF program, `marker.bpf.o` will be generated. Please bear in mind one can enable the program's
debugging output by passing the `DEBUG` option when invoking `make`:

    $ make DEBUG=yes

Debug information will be available on `/sys/kernel/debug/tracing/trace_pipe`.

Also, running utilities such as `objdump(1)` and `ldd(1)` on the generated program is quite informative. We recommend
that you give it a go!

### Achieving portability in the context of eBPF
Put simply, eBPF programs run in a Kernel VM. Now, changes in the kernel types (i.e. addition of `struct` fields)
can really throw eBPF programs in disarray! When an eBPF program is compiled it targets the kernel it was compiled
on, but that needn't be the kernel a client is running...

An initial (and rather popular) approach hinges on compiling these eBPF programs at runtime. This is exactly what
the BPF Compiler Collection (BCC) does. However, this approach comes with its downsides, the main one being that
the target machines need to have a `clang/llvm` installation capable of compiling the eBPF program at runtime.
At the end of this document there's a bit more context on other subtle-yet-important problems with this approach.

Now, the other approach relies on generating relocatable eBPF object code which can then be adapted to the target
kernel. This is possible thanks to the [`libbpf`][libbpf] project. There is one **key** requirement though, the
target kernel **must** expose BPF type information through `/sys/kernel/btf/vmlinux`. This will be the case for
kernels compiled with the `CONFIG_DEBUG_INFO_BTF=y` option. This is the case on a vanilla AlmaLinux 9 installation.
One can also check whether this option was used when compiling the kernel with:

    $ grep CONFIG_DEBUG_INFO_BTF /boot/config-$(uname -r)

If a kernel has not been compiled with this option it should be recompiled to support CO:RE, so the best approach
rapidly becomes going back to [BCC][].

#### What does CO:RE look like?
From the eBPF's program point of view not much changes really. One need stick to 'vanilla' primitives (i.e. no BCC
are available) and the rest pretty much follows. Compilation does require some additional tooling, namely LLVM, Clang
and `libbpf-devel` to get the necessary helpers. On AlmaLinux 9 this can be achieved with:

    # Enable the CRB Repo (check https://wiki.almalinux.org/repos/Extras.html)
    $ dnf install epel-release; dnf config-manager --set-enabled crb

    # Install libbpf together with headers, llvm, clang and the auxiliary bpftool
    $ yum install libbpf-devel libbpf-static clang llvm bpftool

With that, we can compile right away! We just need to generate the `vmlinux.h` header containing the definition of
all kernel structs which can be easily accomplished with:

    $ bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

Bear in mind that we can leverage 'precooked' headers if we need to. This is the case for older kernels, for instance.
Be sure to check [this SO answer][so-vmlinux] and the [btfhub-archive][] repo fora collection of these ready-to-eat
files.

At any rate, we can now generate out relocatable eBPF object code with:

    $ clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c marker.bpf.c -o marker.bpf.o

We're ready to load that `*.o` now! By the way, this section was largely based on [this article][core-example].

##### Bundling libbpf
Given `libbpf` is the one in charge of making runtime transformations, it *should* be installed on client machines.
However, the statically compiled library (i.e. `libbpf.a`) can be embedded into Go binaries so that there are really
no external dependencies whatsoever. This last approach is the one used by [`tracee`][tracee], for instance.

At any rate, if `libbpf` is not bundled the end user can always install it with:

    $ yum install libbpf

That's much lighter than a full blown Clang/LLVM install!

##### Building with libbpf
Given `libbpf` is implemented in C, we need to adjust the environment we compile programs using it on so that
everything works as intended. This basically translates into fixing the compiler and 'telling' it where to
find the `libbpf` headers and libraries:

    $ CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib64/libbpf.a" go build -o libbpfgo-prog

The above example leverages a statically compiled `libbpf` (hence the `*.a` extension), but the idea is
equivalent when targetting shared libraries. Please bear in mind this one-liner has been extracted from
the great documentation [over here][libbpf-build].

##### Are there any downsides?
Well, the most apparent is that one cannot rely on [BCC's Macros][bcc-macros] any more, which means some additional
manual implementations become necessary... However, given the functions defined in [`bpf-helpers(7)`][bpf-helpers]
it's rather feasible to replicate whatever functionality's needed.

### Other considered solutions
Aside from `libbpf`, we also considered leveraging [`ebpf`][ebpf] by the Cilium team which is a great tool in
its own right. However, even though it might be possible, it wasn't obvious (at least for us) from the documentation
how one could leverage a CO:RE model (see [the doc][ebpf-core])... [This discussion][ebpf-disc] also shed some very
valuable information informing this choice.

BCC was a clear contender, but the first-class API is written in Python despite [gobpf][] being available. Again, it's
use would imply 'forcing' Clang/LLVM on whoever wanted to run this!

Native Go implementations of `netlink(7)` such as [`vishvananda/netlink`][go-netlink] offer some [examples][go-netlink-bpf]
on how to load eBPF programs, but they are rather bare-bones and rely on directly interacting with the kernel!

The [`go-tc`][go-tc] project was also taken into consideration, but they bare-bones way in which eBPF programs are to
be defined was a deal breaker too... The documentation even has an [example][go-tc-ebpf] on loading an eBPF program!

### Further reading
Information on eBPF and co. is rather sparse and heavily technical. However, there are some great resources out there
who deserve mentioning. These include articles by Andrii Nakryiko covering [bootstraping `libbpf`][libbpf-bootstrap-blog]
and [CO:RE][core-blog]. The [`libbpf-bootstrap`][libbpf-bootstrap] repository is a treasure trove of information too!

The [BPF series][bpf-series] over at The Gray Node is also a great source!

Please note this directory's contents are largely based on [this example][example] offered by the AquaSecurity team!

We shouldn't forget that, in the end, we're trying to interact with a Linux kernel. This can be accomplished with the
already existing and quite intuitive CLIs that we use on a daily basis. [This example][bpf-cli] shows how all this
can be 'automated' with a small shell script!

Be sure to check the [eBPF docs][ebpf-docs] (especially the section on [`BPF_PROG_TYPE_SCHED_CLS`][BPF_PROG_TYPE_SCHED_CLS])
as they contain a wealth of high-quality, nicely presented information.

<!-- REFs -->
[BCC]: https://github.com/iovisor/bcc
[libbpf]: https://github.com/libbpf/libbpf
[so-vmlinux]: https://stackoverflow.com/questions/76764624/can-i-use-vmlinux-h-in-ebpf-with-non-btf-supported-linux-kernel
[btfhub-archive]: https://github.com/aquasecurity/btfhub-archive/
[core-example]: https://www.sartura.hr/blog/simple-ebpf-core-application
[tracee]: https://github.com/aquasecurity/tracee
[libbpf-build]: https://www.aquasec.com/blog/libbpf-ebpf-programs/
[bcc-macros]: https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
[bpf-helpers]: https://www.man7.org/linux/man-pages/man7/bpf-helpers.7.html
[ebpf]: https://github.com/cilium/ebpf
[ebpf-core]: https://ebpf-go.dev/guides/portable-ebpf/
[gobpf]: https://github.com/iovisor
[libbpf-bootstrap]: https://nakryiko.com/posts/libbpf-bootstrap/
[core-blog]: https://nakryiko.com/posts/bpf-core-reference-guide/
[libbpf-bootstrap]: https://github.com/libbpf/libbpf-bootstrap
[bpf-series]: https://thegraynode.io/posts/bpf_flat_part1/
[ebpf-disc]: https://github.com/cilium/ebpf/discussions/769
[go-netlink]: https://github.com/vishvananda/netlink
[go-neltink-bpf]: https://github.com/vishvananda/netlink/blob/v1.3.0/bpf_linux.go
[go-tc]: https://github.com/florianl/go-tc
[go-tc-ebpf]: https://pkg.go.dev/github.com/florianl/go-tc#example-package-EBPF
[example]: https://github.com/aquasecurity/libbpfgo/tree/main/selftest/tc
[bpf-cli]: https://github.com/xdp-project/bpf-examples/tree/master/tc-basic-classifier
[ebpf-docs]: https://docs.ebpf.io
[BPF_PROG_TYPE_SCHED_CLS]: https://docs.ebpf.io/linux/program-type/BPF_PROG_TYPE_SCHED_CLS/