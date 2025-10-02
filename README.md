# Flowd-go
<!-- [![PkgGoDev](https://pkg.go.dev/badge/github.com/cilium/ebpf)](https://pkg.go.dev/github.com/cilium/ebpf) -->

![FlowyGopher](flowd-go.svg)

<!-- ![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/scitags/flowd-go) -->

Flowd-go is a network flow and packet marking daemon. It is heavily inspired by [`scitags/flowd`](https://github.com/scitags/flowd), but
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

The documentation accompanying `flowd-go` is shipped as a series of Markdown files. You can find all of them with:

    $ find . -path ./vendor -prune -o -name "*.md" -print

Be sure to give those a read for information not covered in this document: we didn't want to make it too long...

## Dependencies
Flowd-go has no dependencies in the sense that `libbpf` is included through a statically compiled binary. However, `libbpf` does depend on
both `libz` and `libelf` for working as set forth in the [kernel documentation](https://www.kernel.org/doc/html/v5.14/bpf/libbpf/libbpf_build.html)
and in the [`libbpf` mirror](https://github.com/libbpf/libbpf) itself.

These dependencies are taken into account in the RPM (i.e. installing `flowd-go` through an RPM) so that you don't have to worry about a thing.
However, these dependencies are rather common and chances are they're already present on the system as they're required by the likes of
`dnf(8)` and `systemd(1)`.

### Running on non-RHEL distributions
In order to successfully run `fowd-go` on non-RHEL systems (i.e. Ubuntu and co.) you must ensure the dependencies outlined above are met. You'll
need to manually install them in case they're missing but, again, chances are they're already present. You can check whether that's the case
by leveraging `ldd(1)` to find any missing dependencies.

## Quickstart
The golden rule is that 'if something can be done, then a `make` target can be leveraged for it'. This basically means that compiling, running,
generating the documentation and all those common tasks can be accomplished by simply issuing the appropriate `make <target>`. To get an
updated list of targets simply run:

    $ make

This will provide more comprehensive information than we can include here. At any rate, the following lines go a bit more in depth into what's
actually going on when compiling and running the code. There's also a section devoted to leveraging the purposefully built Docker containers
to develop and test the code!

The code base should be compilable both on Linux and Darwin (i.e. macOS) machines. Bear in mind the eBPF backend won't be available on macOS machines by
design as it's a feature of the Linux kernel. In order to support eBPF the following must be installed on a Linux-based machine. We're working on
AlmaLinux 9.4, where the following installs all needed dependencies:

    # Enable the CRB Repo (check https://wiki.almalinux.org/repos/Extras.html)
    $ dnf install epel-release; dnf config-manager --set-enabled crb

    # Install libbpf together with headers and the static library (i.e. *.a), llvm, clang and the auxiliary bpftool
    $ yum install libbpf-devel libbpf-static clang llvm bpftool

    # If you want to leverage clangd and bear(1) to enable the LSP server for eBPF programs you can also install
    $ yum install clang-tools-extra bear

If you want to create the manpage you'll also need to install [`go-md2man`](https://github.com/cpuguy83/go-md2man), which will convert the
Markdown-formatted manpage into a Roff-formatted one:

    # We can install the tool like any other one. Just bear in mind you should
    # include Go's binary installation directory in your PATH. You can also
    # specify the installation path through the GOBIN environment variable.
    go install github.com/cpuguy83/go-md2man/v2@latest

Back in the day we leveraged [`pandoc`](https://pandoc.org), but given it's released only on EPEL we couldn't add it as a dependency on
the Koji instance we have to build our packages on. This led us find an alternative solution.

Also, if you want to build an RPM with all the necessary goodies be sure to install these additional dependencies:

    $ yum install rpm-build rpm-devel rpmlint rpmdevtools

You can now create the necessary build infrastructure by simply running:

    $ rpmdev-setuptree

Be sure to check the [RPM Packaging Guide](https://rpm-packaging-guide.github.io) for a wealth of great information.

With all the above out of the way, one can leverage the `Makefile` with:

    $ make build

The above will produce the `flowd-go` binary which one can run as usual with:

    $ ./bin/flowd-go --conf cmd/conf.json --log-level debug run

Please bear in mind that if the eBPF backend is in use the binary should be started with privileges (i.e. by prepending `sudo(8)`). We are looking into
setting the binaries `capabilities(7)` so that elevated permissions are not needed. Also, one can run `make` or `make help` to get a list of available
targets together with an explanation on what they achieve.

Also, be sure to run the following to be greeted with a help message showing you what other commands besides `run` are available. You can also check
the Markdown-formatted manpage on `rpms/flowd-go.1.md` to get a list of available flags and commands along a more detailed description.

## Releasing
All the documentation regarding how to make a release can be found on [`rpm/README.md`](./rpm/README.md). The bottom line is that both
a regular GitHub-CI-based release and a CERN Koji-based release will be made.

### Not so quickstart
One can also leverage Docker containers to run `flowd-go`. However, given we'll be making use of some rather advanced technologies in the sense that
they are not for every day use, we'll need to do some convincing so that the containers can actually run as expected. In order to maintain a sane
degree of security, Docker containers are started with very few `capabilities(7)` by default. Things like loading eBPF programs and creating qdiscs
require a great deal of privileges which we don't really have by default. The good news is we can just 'ask' for these capabilities, the bad news
is that the resulting command is a bit frightening...

Please bear in mind the following has been **only tested** on Docker Desktop 4.30.0 running on macOS 13.5.1: YMMV!

#### Docker, docker, docker!
We have added three targets (i.e. `docker-{start,shell,stop}`) taking care of automating the following discussion away. With this, the workflow
boils down to:

    # Start the container in the background
    $ make docker-start

    # Open as many shells as you want in that container
    $ make docker-shell

    # Stop (and implicitly remove) the container
    $ make docker-stop

Bear in mind you can explicitly request one of the other available container flavours by specifying a value for the `FLAVOUR` variable:

    # By default, invoking 'make docker-start' with no other arguments would be the same as running
    $ make FLAVOUR=dev

    # You can also run the image used for testing in the CI
    $ make FLAVOUR=test

    # And you can also take the image used for releases on the CI for a spin
    $ make FLAVOUR=release

If in doubt, be sure to skim over `mk/docker.mk` to take a look at what's actually being run with the above targets. For more information
on what each image flavour is trying to accomplish please check the [What's what? section](#whats-what) below.

The following paragraphs explain a bit more in depth what's actually going on behind the scenes in case you'd rather set things up yourself.

#### What if I despise Makefiles?
Without further ado:

    $ docker run -v $(pwd):/root/flowd-go --cap-add SYS_ADMIN --cap-add BPF --cap-add NET_ADMIN -it --rm --name flowd-go ghcr.io/scitags/flowd-go:dev-v2.0 bash

To get an idea of what each option accomplishes be sure to taje a look at `mk/docker.mk`.

With the above we should be dropped into a working shell where we can just run:

    $ cd flowd-go; make build; ./bin/flowd-go --conf cmd/conf.json --log-level debug run

As always, we can open more shells in the same container with:

    $ docker exec -it flowd-go bash

Now, if we want to have access to the eBPF program's debug output on a machine running Docker Desktop we need to manually mount
the `debugfs` filesystem (see `mount(8)`). On Linux-based machines, `debugfs` should be mounted by default and these next steps
should not be necessary. Anyway, we can mount `debugfs` manually by running the following within the container:

    $ mount -t debugfs debugfs /sys/kernel/debug

We can also do the same thing persistently by running:

    $ docker volume create --driver local --opt type=debugfs --opt device=debugfs debugfs

Then, we just need to add the following when invoking `docker run ... bash` to mount this new filesystem:

    -v debugfs:/sys/kernel/debug:rw

Please be sure to check [this site](https://hemslo.io/run-ebpf-programs-in-docker-using-docker-bpf/) which contains very valuable
info on this topic! All in all, getting Docker to work with eBPF machinery can be a bit of a pain, but the payback is huge!

## Configuration
As you see above, we need to provide the path to a JSON-formatted configuration file. We provide a sample on `cmd/conf.json` which should be suitable
for locally running `flowd-go` to check everything's working as intended. If left unspecified, `flowd-go` will look for a configuration file at
`/etc/flowd-go/conf.json`. For more information on what can be configured, please refer to the Markdown-formatted manpage on `rpms/flowd-go.1.md`.

Also, each plugin and backend will have a bit of documentation in their respective directories which is worth a read.

## Architecture
`Flowd-go` follows `flowd`'s architecture in that its core revolves around the idea of plugins and backends. An external user or program can specify *flow events*
through the configured plugins and these events will be propagated to the backends, where each of them will carry out the action they are supposed to do.
Please refer to each plugin's or backend's documentation to find out what it is they expect/do.

Within `flowd-go`, a flow event is represented as a `struct` as defined on `types.go`:

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

Internally, `flowd-go` makes heavy use of Go's [channels](https://go.dev/doc/effective_go#channels) and built-in concurrency constructs to handle the inner workings
in the simplest and most elegant way we could think of.

Another key aspect separating `flowd-go` from `flowd` is how the eBPF plugin is implemented. In the latter, the eBPF program's source code is embedded into the source
code and every time the program starts the eBPF program is compiled on the running machine. This of course implies the machine must have available a full-blown
`clang` and `llvm` installation to gether with the `bcc` headers. On the other hand, `flowd-go` leverages `libbpf`, a thin C-based library handling the loading of
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

Please note these machines require no runtime dependencies if `libbpf` is bundled with `flowd-go`.

## What's what?
This project strives to adhere to Go's best practices in terms of module organisation as outlined [here](https://go.dev/doc/modules/layout). Thus, it can be
a bit overwhelming for people not familiar with Go's ecosystem. The following sheds some light on what-goes-where:

- `.`: The main `flowd-go` module containing the type definitions and other utilities.
- `settings`: A separate module handling the parsing of the configuration needed to avoid circular dependencies.
- `cmd`: The `flowd-go` binary itself. It pulls dependencies from all over the repo.
- `backends`: The implementations of the available backends. Each of them is an independent Go module.
- `plugins`: The implementations of the available plugins. Each of them is an independent Go module.
- `enrichment`: Implementation of several Linux interfaces allowing us to gather low-level information on ongoing connections.

Other than that, we also have pother couple of directories with auxiliary files:

- `rpm`: This directory contains all the goodies for bundling up RPM packages for distribution, including:
    - `flowd-go.1.md`: The Markdown-formatted manpage for `flowd-go`. It's converted into a normal Roff-formatted manpage by `go-md2man`.
    - `flowd-go.service`: The SystemD Unit file for running `flowd-go` as a regular SystemD service.
    - `conf.json`: A configuration file meant for deployment on real machines. For development the configuration one should use
      is located on `cmd/conf.json`.

- `flowd-go.spec`: The RPM spec file used to build RPMs to make `flowd-go` easily available on RHEL-like systems.

- `mk`: Several auxiliary `Makefiles` which are included from the main `Makefile` that provide convenient automations for several
  interactions we usually carry out with `flowd-go` when developing it.

- `dockerfiles`: The different Dockerfiles we use to build the images used by the project. The current flavours are:
    - `dev`: A development image based on `almalinux/9.4` that includes everything necessary to work on and develop flowd-go locally.
    - `test`: A lean image based on `almalinux/9.4-minimal` including the bare minimum needed to build flowd-go and check things are okay.
    - `release`: A lean image based on the previous one which also adds dependencies needed for RPM packaging.

As usual, you can check all the available images and their versions [here](https://github.com/scitags/flowd-go/pkgs/container/flowd-go).

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

## On building RPM packages
Building RPM packages is an adventure full of twists and turns. We've documented the main references once should become acquainted
with on `mk/rpm.mk`. For WLCG-compliant distribution we need to leverage CERN's Koji instance. [Koji](https://docs.pagure.org/koji/)
is a system for building RPMs which leverages [mock](https://rpm-software-management.github.io/mock/) under the hood for all the
heavy lifting.

The use of the aforementioned tools implies one needs to closely comply with the standard procedures for building RPMs as set forth
in the official RPM documentation as well as in Fedora's documentation. All these sites are linked in the aforementioned `rpm.mk`.

All in all, one should be able to build an RPM bundling flowd-go locally by running the following after having installed `mock` and
`rpmbuild`:

    $ make rpm-mock

If the command fails be sure to study its output: it's verbosy and a bit hard to read but extremely helpful and informative.

## Kudos
The logo is a composition of a couple of images:

- [Go's Gopher](https://github.com/golang-samples/gopher-vector/blob/master/gopher.svg)
- [A Vector Field](https://commons.wikimedia.org/wiki/File:Vector_field.svg)

These were handled with [Inkscape](https://inkscape.org).

## Questions or comments?
Feel free to reach me over at <pcolladosoto@gmx.com> or open up an issue on the repo. PRs are also welcome!
