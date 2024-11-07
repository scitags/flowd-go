# Glowd
Glowd is a network flow and packet marking daemon. It is heavily inspired by [`scitags/flowd`](https://github.com/scitags/flowd), but
instead of Python it's implemented in Go.

Why reimplement something that's already working? Well, because...

- ... we wanted to try our hand at implementing the flow marking infrastructure leveraging vanilla eBPF instead of BCC.
- ... Go produces statically compiled binaries which make it much easier to deploy on target machines: we don't need containerisation!
- ... Go lends itself very well to the model underlying the solution where channel-based concurrency feels natural.
- ... Go allows for known-to-work concurrency to be implemented making scaling for high load scenarios easily achievable.
- ... the SciTags effort might find our work useful!

Given the heavy drawing from `flowd` the original authors have been included in the LICENSE and other documents to make that
fact explicit. We apologise in advance for any oversights in this front...

The technical specification we try to adhere to can be found [here](https://docs.google.com/document/d/1x9JsZ7iTj44Ta06IHdkwpv5Q2u4U2QGLWnUeN2Zf5ts/edit).
The [SciTags Organization](https://www.scitags.org/) is the entity behind this effort of tagging network traffic to get better insights into how
network flows behave in the search of strategies for optimizing data delivery in data-heavy realms such as that of High Energy Physics (HEP).

## Quickstart
The code base should be compilable both on Linux and Darwin (i.e. macOS) machines. Bear in mind the eBPF backend won't be available on macOS machines by
design as it's a feature of the Linux kernel. In order to support eBPF the following must be installed on a Linux-based machine. We're working on
AlmaLinux 9.4, where the following installs all needed dependencies:

    # Enable the CRB Repo (check https://wiki.almalinux.org/repos/Extras.html)
    $ dnf install epel-release; dnf config-manager --set-enabled crb

    # Install libbpf together with headers and the static library (i.e. *.a), llvm, clang and the auxiliary bpftool
    $ yum install libbpf-devel libbpf-static clang llvm bpftool

If you want to create the manpage you'll also need to install [`pandoc`](https://pandoc.org), which will convert the Markdown-formatted
manpage into a Roff-formatted one:

    # On Almalinux you can install pandoc from EPEL
    $ yum install pandoc

    # On macOS you can install it with Homebrew or an equivalent package manager
    $ brew install pandoc

Also, if you want to build an RPM with all the necessary goodies be sure to install these additional dependencies:

    $ yum install rpm-build rpm-devel rpmlint rpmdevtools

You can now create the necessary build infrastructure by simply running:

    $ rpmdev-setuptree

Be sure to check the [RPM Packaging Guide](https://rpm-packaging-guide.github.io) for a wealth of great information.

With all the above out of the way, one can leverage the `Makefile` with:

    $ make build

The above will produce the `glowd` binary which one can run as usual with:

    $ ./bin/glowd --conf cmd/conf.json --log-level debug run

Please bear in mind that if the eBPF backend is in use the binary should be started with privileges (i.e. by prepending `sudo(8)`). We are looking into
setting the binaries `capabilities(7)` so that elevated permissions are not needed. Also, one can run `make` or `make help` to get a list of available
targets together with an explanation on what they achieve.

Also, be sure to run the following to be greeted with a help message showing you what other commands besides `run` are available. You can also check
the Markdown-formatted manpage on `glowd.1.md` to get a list of available flags and commands along a more detailed description.

## Configuration
As you see above, we need to provide the path to a JSON-formatted configuration file. We provide a sample on `cmd/conf.json` which should be suitable
for locally running `glowd` to check everything's working as intended. If left unspecified, `glowd` will look for a configuration file at
`/etc/glowd/conf.json`. For more information on what can be configured, please refer to the Markdown-formatted manpage on `glowd.1.md`.

Also, each plugin and backend will have a bit of documentation in their respective directories which is worth a read.

## Architecture
`Glowd` follows `flowd`'s architecture in that its core revolves around the idea of plugins and backends. An external user or program can specify *flow events*
through the configured plugins and these events will be propagated to the backends, where each of them will carry out the action they are supposed to do.
Please refer to each plugin's or backend's documentation to find out what it is they expect/do.

Within `glowd`, a flow event is represented as a `struct` as defined on `types.go`:

```go
type FlowID struct {
    State      FlowState
    Protocol   Protocol
    Src        IPPort
    Dst        IPPort
    Experiment uint32
    Activity   uint32
    StartTs    time.Time
    EndTs      time.Time
    NetLink    string
}
```

Each of the fields is documented on the source file itself, but the gist of it is that these `flowID`s contain the source and destination addresses and ports
together with the transport level protocol and the experiment and activity identifiers. Thy can be regarded as a 5-tuple to 2-tuple mapping where we identify
datagrams/segments with the 5 first values and then somehow 'mark' that flow with the latter two.

Internally, `glowd` makes heavy use of Go's [channels](https://go.dev/doc/effective_go#channels) and built-in concurrency constructs to handle the inner workings
in the simplest and most elegant way we could think of.

Another key aspect separating `glowd` from `flowd` is how the eBPF plugin is implemented. In the latter, the eBPF program's source code is embedded into the source
code and every time the program starts the eBPF program is compiled on the running machine. This of course implies the machine must have available a full-blown
`clang` and `llvm` installation to gether with the `bcc` headers. On the other hand, `glowd` leverages `libbpf`, a thin C-based library handling the loading of
a pre-compiled eBPF program so that it can run on different kernels. This is the basis of the Compile Once Run Everywhere (CO:RE) paradigm. The compilation of
the eBPF program is done on a machine including `libbpf`'s headers and a statically-compiled implementation of the library so that there are truly no runtime
dependencies: the precompiled eBPF program si also embedded into the binary! For a deeper and thoroughly referenced discussion be sure to refer to the documentation
of the eBPF backend.

This eBPF backend has been shown to run on the following distros and kernels. The eBPF program is always compiled on a machine running `AlmaLinux 9.4` with the
`5.14.0-427.24.1.el9_4.x86_64` Linux kernel release as given by `uname(1)` and `libbpf-2:1.3.0-2.el9`:

|        Distro | Kernel Release                 |
| ------------: | :----------------------------- |
| AlmaLinux 9.4 | `5.14.0-427.24.1.el9_4.x86_64` |
|     Fedora 35 | `6.11.3`                       |

Please note these machines require no runtime dependencies if `libbpf` is bundled with `glowd`.

## What's what?
This project strives to adhere to Go's best practices in terms of module organisation as outlined [here](https://go.dev/doc/modules/layout). Thus, it can be
a bit overwhelming for people not familiar with Go's ecosystem. The following sheds some light on what-goes-where:

- `.`: The main `glowd` module containing the type definitions and other utilities.
- `settings`: A separate module handling the parsing of the configuration needed to avoid circular dependencies.
- `cmd`: The `glowd` binary itself. It pulls dependencies from all over the repo.
- `backends`: The implementations of the available backends. Each of them is an independent Go module.
- `plugins`: The implementations of the available plugins. Each of them is an independent Go module.

Other than that, we also have some weird-looking files here and there:

- `glowd.1.md`: The Markdown-formatted manpage for `glowd`. It's converted into a normal Roff-formatted manpage by `pandoc`.
- `glowd.service`: The SystemD Unit file for running `glowd` as a regular SystemD service.
- `glowd.spec`: The RPM spec file used to build RPMs to make `glowd` easily available on RHEL-like systems.

And to finish up we have a ton of `Makefiles` on the `mk` directory. These are pulled in by the main `Makefile` and provide
convenient automations for several interactions we usually carry out with `glowd` when developing it.

## Adding new backends or plugins
The code has been designed so that adding new plugins and backends is as easy as possible. Leaving configuration aside (which you can
learn more about by looking at the implementation of any plugin and/or backend) you just need to provide something that adheres to the
appropriate [interfaces](https://go.dev/doc/effective_go#interfaces) defined on `types.go`:

```go
type Backend interface {
	Init() error
	Run(<-chan struct{}, <-chan FlowID)
	Cleanup() error
}

type Plugin interface {
	Init() error
	Run(<-chan struct{}, chan<- FlowID)
	Cleanup() error
}
```

These are more documented on the source code.

## Questions or comments?
Feel free to reach me over at <pcolladosoto@gmx.com> or open up an issue on the repo. PRs are also welcome!
