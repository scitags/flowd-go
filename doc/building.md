# Building flowd-go
One of Go's most advantageous features is how easy it is to generate statically compiled binaries.
You can pretty much compile it once and run it everywhere, which is quite a nifty feature.

However, when one leverages [`cgo`][cgo] all sorts of things can begin to go awry. In our particular
use case there is not too much wiggle room: we **must** interact with `libbpf` to do all the eBPF
heavy-lifting, so we have to jump though these cgo-induced hoops...

The following tries to shed some light into the process and tradeoffs one has to consider.

## Are Go programs really statically compiled?
Well... not really! By default `cgo` is enabled when targetting the system the program's being built
on as explained in the [documentation][cgo]. One can however avoid this default behaviour by
specifying the `CGO_ENABLED=0` variable when invoking `go` as in

    $ CGO_ENABLED=0 go build

By default binaries will depend on the system's C implementation (i.e. `libc`) as shown by
[`ldd(1)`][ldd]:

    $ go build -o mybin && ldd mybin
        linux-vdso.so.1 (0x00007ffc05973000)
        libc.so.6 => /lib64/libc.so.6 (0x00007fa860800000)
        libresolv.so.2 => /lib64/libresolv.so.2 (0x00007fa860a75000)
        /lib64/ld-linux-x86-64.so.2 (0x00007fa860a9e000)

If disabling `cgo` one instead sees

    $ CGO_ENABLED=0 go build -o mybin && ldd mybin
        not a dynamic executabl

Another path through which one can implicitly come to depend on the system's `libc` is
if using the [`net`][net] package. As explained in its [documentation][net], one should
use the `netgo` tag to avoid depending on the system's `libresolv`

    $ CGO_ENABLED=0 go build -o mybin -tags netgo

The above should produce a purely static binary even if leveraging the `net` package.

One could enter a lengthy discussion on whether it even makes sense to go for a purely
static binary when all you depend on is `libc` (which is itself integral to pretty much
any common distribution), but that's another story.

## Out particular case
We **must** enable `cgo` given our dependency on `libbpf` through `libbpfgo`; there's no
way around it. This would in principle mean that we cannot get away with a purely static
binary... or can we?

Before going down the static-binary rabbit hole let's talk a bit about `flowd-go`'s current
dependencies:

    $ ldd bin/flowd-go
        linux-vdso.so.1 (0x00007ffc2eb6e000)
        libresolv.so.2 => /lib64/libresolv.so.2 (0x00007f3fd76d7000)
        libelf.so.1 => /lib64/libelf.so.1 (0x00007f3fd76bc000)
        libz.so.1 => /lib64/libz.so.1 (0x00007f3fd76a2000)
        libc.so.6 => /lib64/libc.so.6 (0x00007f3fd7400000)
        libzstd.so.1 => /lib64/libzstd.so.1 (0x00007f3fd7329000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f3fd7700000)

Aside from the regular `libc`-related suspects we have three more dependencies, namely on
`libelf`, `libz` and `libzstd`. Where could these be coming from? They're introduced
by `libbpf` of course! This is stated on [its GitHub mirror][libbpf] and the
[kernel's documentation][libbpf-doc]. The dependency on `libzstd` is actually
introduced implicitly by `libelf`, but you get the idea.

Now, what you may be wandering is how on Earth is `libbpf` introducing dependencies when
it's compiled in as a static library. It's crucial to remember that `libbpf` is indeed
statically included in the binary, but its dependencies are not. This explains what `ldd(1)`
is showing us.

### But... there are no explicit dependencies on the SPEC file!
That's true, but that's by design. If one reads the [RPM documentation][rpm-doc] it explicitly
states that whatever's reported by running `ldd(1)` on all the RPM's files is automatically
included as a dependency without an explicit `Requires:` directive in the SPEC file.

For us, this is adding the dependency on `elfutils-libelf` and `zlib`. The `elfutils-libelf`
package depends on `libzstd` and so we come full circle. We can check that with `dnf(8)`
after having added CERN's repository (check [the RPM documentation](../rpm/README.md)):

    $ dnf repoquery --requires flowd-go
    Last metadata expiration check: 3:42:56 ago on Mon Jul 21 18:51:31 2025.
    /bin/sh
    ld-linux-aarch64.so.1()(64bit)
    ld-linux-aarch64.so.1(GLIBC_2.17)(64bit)
    libc.so.6(GLIBC_2.34)(64bit)
    libelf.so.1()(64bit)
    libelf.so.1(ELFUTILS_1.0)(64bit)
    libelf.so.1(ELFUTILS_1.3)(64bit)
    libelf.so.1(ELFUTILS_1.5)(64bit)
    libelf.so.1(ELFUTILS_1.6)(64bit)
    libresolv.so.2()(64bit)
    libz.so.1()(64bit)
    libz.so.1(ZLIB_1.2.3.3)(64bit)
    rtld(GNU_HASH)

So, on RPM-based distros everything's fine as long as we install the RPM: dependencies will
be correctly resolved for us.

## Why has it worked till now?
Because our dependencies are rather common. Tools like `dnf(8)` depend on `libelf` and others
like `sudo(8)` depend on `libz` just to name a few. Even if we didn't explicitly require them
chances are they're already present in whatever system we decide to target. The same goes for
`libc` which is probably integral to most of the system's tools.

Even though we are not as experienced on Debian-based distros, chances are these libraries are
as important there as well. They should however be installed to make sure everything works as
intended though...

## Trying to compile stuff statically
Trying to compile a binary in a purely static fashion usually requires two steps:

1. Go on a Dragon Ball-esque hunt for the statically-compiled dependencies.
1. Invoke the linker with the necessary flags to find (and use) these static libs.

Even though these two might sound innocent enough, the reality is it's quite convoluted
some times... At this point in time (check the last commit's timestamp) the first step
turns into:

1. `libz`: install `zlib-static` with `dnf(8)`.
1. `libc`: install `glibc-static` with `dnf(8)`.
1. `libbpf`: install `libbpf-static` with `dnf(8)`.
1. `libelf`: download the necessary [`elfutils` release][elfutils-release] and manually
   compile it to generate the necessary `libelf.a`. Note the absolute path to its containing
   directory for when we invoke `ld(1)`.
1. `libzstd`: download the necessary [`zstd` release][zstd-release] and manually
   compile it to generate the necessary `libzstd.a`. Note the absolute path to its containing
   directory for when we invoke `ld(1)`.

All these steps should be carried out by running `make deps` from the root of the repository.

Once you have all the ingredients ready, you can then try to compile `flowd-go`
in a static fashion with the following (laughably long) invocation:

    $ CGO_CFLAGS="-I/usr/include/bpf"                                                                                 \
        CGO_LDFLAGS="-L./deps/elfutils-0.193/libelf -L./deps/zstd-1.5.5/lib -static -lelf -lz -lzstd -lbpf --verbose" \
        CC="clang" CGO_ENABLED="1" GOARCH=amd64 go build  -o ./bin/flowd-go                                           \
        -tags ebpf,netgo                                                                                              \
        -ldflags '-X main.builtCommit=63bf3b7 -X main.baseVersion=v2.2.0 -w -extldflags "-static"'                    \
        ./cmd

This produces `./bin/flowd-go` which has indeed no runtime dependencies:

    $ ldd ./bin/flowd-go
        not a dynamic executable

## Is it worth it?
Put simply, not really. The dependencies introduced by `libbpf` are 'core' libraries which will probably be present on
the target system anyway. It's nice to know we can produce a truly static binary though...

<!-- REFs -->
[cgo]: https://pkg.go.dev/cmd/cgo
[ldd]: https://www.man7.org/linux/man-pages/man1/ldd.1.html
[net]: https://pkg.go.dev/net
[libbpf]: https://github.com/libbpf/libbpf
[libbpf-doc]: https://www.kernel.org/doc/html/v5.14/bpf/libbpf/libbpf_build.html
[rpm-doc]: https://rpm.org/docs/4.19.x/manual/more_dependencies.html
[elfutils-release]: https://sourceware.org/elfutils/ftp/
[zstd-release]: https://github.com/facebook/zstd/releases
