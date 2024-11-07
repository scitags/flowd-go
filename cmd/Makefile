# ********************************************************************* #
# Be sure to check what tracee (https://github.com/aquasecurity/tracee) #
# does for compiling. It basically compiles libbpf itself! Just clone   #
# and compile it to get the commands used in the process.               #
# ********************************************************************* #

# The Go compiler to use
GOC = go

# The compiler to use for the BPF side of things
CC = clang

# Configure this release's verision and commit
# VERSION = $(shell git describe --tags --abbrev=0)
COMMIT = $(shell git rev-parse --short HEAD)

# Where whouls we place output binaries?
BIN_DIR = ./bin

# Name of the output binary
BIN_NAME = glowd

SOURCES = $(wildcard *.go)
TRASH   = $(BIN_DIR)/* cmd

# Markdown-formatted manpage to parse with pandoc.
DOC_FILE = $(BIN_NAME).1.md

# Path of the buildroot created with rpmdev-setuptree.
RPM_BUILDROOT = $(shell echo ${HOME})/.rpmbuild

# Default compilation flags.
# The `-ldflags` option lets us define global variables at compile time!
# Check https://stackoverflow.com/questions/11354518/application-auto-build-versioning
CFLAGS := -tags ebpf -ldflags "-X main.builtCommit=$(COMMIT)" -o $(BIN_DIR)/$(BIN_NAME)

# Adjust GOC's environment depending on what OS we're on to deal with
# all the BPF machinery. Note that when ENV_FALGS is not defined on
# Darwin everything will work as expected!
OS := $(shell uname)
ifeq ($(OS),Linux)
	ENV_FLAGS := $(ENV_FLAGS) CGO_CFLAGS="-I/usr/include/bpf"

	# Maybe we need the -L? Check it!
	# Check the output binary has no dependency on libbpf with
	# ldd(1) when linking to the static library. Also, note the version
	# of libbpfgo we're working with expects libbpf 1.4.3 whilst the
	# one bundled with AlmaLinux is 1.3.2. As long as we don't call into
	# new methods this should be okay, but it's something to keep in mind...
	# Maybe the best solution is to simply link into the libbpf version
	# bundled with libbpfgo instead of the one we're using now which is
	# provided by the libbpf-static package?
	ENV_FLAGS := $(ENV_FLAGS) CGO_LDFLAGS="/usr/lib64/libbpf.a"
	ENV_FLAGS := $(ENV_FLAGS) CC="$(CC)"

	# This is not really needed, but we'd rather be explicit!
	ENV_FLAGS := $(ENV_FLAGS) CGO_ENABLED="1"
endif

help:
	@echo "usage: make <target>"
	@echo "targets:"
	@echo "             build: build the binary for {linux,darwin}/amd64"
	@echo "                    the target OS is determined by the one make"
	@echo "                    is ran on."
	@echo ""
	@echo "               doc: build and compress the manpage."
	@echo ""
	@echo "               rpm: build the RPM. Make sure the machine this runs on has a"
	@echo "                    RPM buildroot configured through rpmdev-setuptree."
	@echo ""
	@echo "           tc-show: show information gathered through tc(8) pertaining the eBPF backend."
	@echo "          tc-clean: remove the qdisc implicitly created when loading the eBPF program."
	@echo "        ebpf-trace: show the contents of the kernel's trace pipe where the"
	@echo "                    debug information of eBPF programs is dumped."
	@echo "   start-ipv4-flow: write to glowd's named pipe to strart an IPv4 flow."
	@echo "     end-ipv4-flow: write to glowd's named pipe to end an IPv4 flow."
	@echo "   start-ipv6-flow: write to glowd's named pipe to strart an IPv6 flow."
	@echo "     end-ipv6-flow: write to glowd's named pipe to end an IPv6 flow."
	@echo "  start-dummy-flow: send an HTTP GET reuqest to glowd's API to start an IPv6 flow."
	@echo "    end-dummy-flow: send an HTTP GET reuqest to glowd's API to end an IPv6 flow."
	@echo ""
	@echo "             clean: delete everything defined as rubbish."

# Simply build the command
build: $(SOURCES)
	@mkdir -p bin
	$(ENV_FLAGS) $(GOC) build $(CFLAGS)

doc: $(DOC_FILE)
	@echo "Building documentation"
	@pandoc --standalone --to man $(DOC_FILE) | gzip > $(basename $(DOC_FILE)).gz

.PHONY: clean tc-show tc-clean start-ipv4-flow end-ipv4-flow start-ipv6-flow end-ipv6-flow \
	start-dummy-flow end-dummy-flow rpm

# Check https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
# for a great discusson on tc introspection!
tc-show:
	@echo QDisc:
	@sudo tc qdisc show dev lo
	@echo Ingress filters:
	@sudo tc filter show dev lo ingress
	@echo Egress filters:
	@sudo tc filter show dev lo egress

tc-clean:
	@sudo tc qdisc del dev lo clsact

ebpf-trace:
	@sudo cat /sys/kernel/debug/tracing/trace_pipe

start-ipv4-flow:
	@sudo bash -c 'echo "start tcp 192.168.0.1 2345 127.0.0.1 5777 1 2" > np'

end-ipv4-flow:
	@sudo bash -c 'echo "end tcp   192.168.0.1 2345 127.0.0.1 5777 1 2" > np'

start-ipv6-flow:
	@sudo bash -c 'echo "start tcp         ::1 2345       ::1 5777 1 2" > np'

end-ipv6-flow:
	@sudo bash -c 'echo "end tcp           ::1 2345       ::1 5777 1 2" > np'

start-dummy-flow:
	curl http://localhost:7777/dummy/start

end-dummy-flow:
	curl http://localhost:7777/dummy/end

rpm: linux doc
	@echo "Building RPM with buildroot $(RPM_BUILDROOT)"
	@echo "Copying artifacts to the RPM buildroot..."
	@cp $(BIN_DIR)/$(BIN_NAME)     $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME)
	@cp conf.json                  $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).json
	@cp $(BIN_NAME).service        $(RPM_BUILDROOT)/SOURCES/$(BIN_NAME).service
	@cp $(basename $(DOC_FILE)).gz $(RPM_BUILDROOT)/SOURCES/$(basename $(DOC_FILE)).gz
	@echo "Building the RPM..."
	@rpmbuild -bb $(RPM_BUILDROOT)/SPECS/wlcg-site-snmp.spec


clean:
	@rm -rf $(TRASH)
