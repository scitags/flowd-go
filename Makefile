# ********************************************************************* #
# Be sure to check what tracee (https://github.com/aquasecurity/tracee) #
# does for compiling. It basically compiles libbpf itself! Just clone   #
# and compile it to get the commands used in the process.               #
# ********************************************************************* #

# The Go compiler to use
GOC = go

# The compiler to use for the BPF side of things
CC = clang

# Please note this environment variable will only be defined when running
# the %build scriptlet of a SPEC file during the building of RPM packages.
# Given the context in which those builds run IS NOT that of a full-fledged
# repository we do need to make some (slight) changes.
ifdef RPM_PACKAGE_NAME
$(info running in an RPM context!)
BUILDING_RPM := 1
endif

# Get the current tag to embed it into the Go binary. We'll drop the
# initial v so as to get a 'clean' version number (i.e. 1.0 instead
# of v1.0). We'll however 'force' the version as this can clash when
# working on tagged branches... We do need to figure out a better way
# to propagate all this to the SPEC file and so on...
# VERSION = $(shell git describe --tags --abbrev=0 | tr -d v)
ifdef BUILDING_RPM
VERSION := $(RPM_PACKAGE_VERSION)
else
VERSION = 2.0
endif

# The version to embed in image tags. Note this is exported so that both the
# recursive image building and the use of images can leverage it.
DOCKER_IMG_VERSION := v2.0
export DOCKER_IMG_VERSION

# Get the current commit to embed it into the Go binary.
ifdef BUILDING_RPM
COMMIT = $(shell cat commit)
else
COMMIT = $(shell git rev-parse --short HEAD)
endif

# Where whouls we place output binaries?
BIN_DIR = ./bin

# Name of the output binary
BIN_NAME = flowd-go

# Path to wher the main package lives
MAIN_PACKAGE = ./cmd

# Source files to keep an eye out for for knowing when to rebuild the binary.
# This is not really honoured at the moment, but we'll look into that at some
# point...
SOURCES = $(wildcard *.go)

# What to remove when cleaning up
TRASH   = $(BIN_DIR)/* rpms/*.gz rpms/*.rpm

# Default compilation flags.
# The `-ldflags` option lets us define global variables at compile time!
# Check https://stackoverflow.com/questions/11354518/application-auto-build-versioning
CFLAGS := -tags ebpf -ldflags "-X main.builtCommit=$(COMMIT) -X main.baseVersion=$(VERSION)"

# Path to the different directories containing eBPF sources needed by flowd-go. Make will be
# invoked recursively there!
EBPF_BACKEND_PROGS_PATH := backends/ebpf/progs
EBPF_ENRICHMENT_PROGS_PATH := enrichment/skops/progs

# Adjust GOC's environment depending on what OS we're on to deal with
# all the BPF machinery. Note that when ENV_FLAGS is not defined on
# Darwin everything will work as expected!
OS := $(shell uname)
ifeq ($(OS),Linux)
# Include the bpf headers from the kernel!
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
	@echo "                    is ran on. You can specify the debug option"
	@echo "                    with DEBUG=yes to include debugging information"
	@echo "                    on the eBPF program. To do that you can simply"
	@echo "                    invoke make with 'make DEBUG=yes'."
	@echo ""
	@echo "           rpm-dbg: show the value of variables leveraged when building"
	@echo "                    the RPMs."
	@echo "          rpm-dist: bundle all the necessary sources in a *.tar.gz file"
	@echo "                    which will be embedded in a SRPM."
	@echo "           rpm-src: create a SRPM."
	@echo "           rpm-bin: create a binary RPM."
	@echo "          rpm-mock: leverage mock to build the RPM, mimicking what Koji will do."
	@echo "         rpm-clean: clean the directories leveraged to build all the RPM stuff."
	@echo ""
	@echo "           tc-show: show information gathered through tc(8) pertaining the eBPF backend."
	@echo "          tc-clean: remove the qdisc implicitly created when loading the eBPF program."
	@echo "        ebpf-trace: show the contents of the kernel's trace pipe where the"
	@echo "                    debug information of eBPF programs is dumped."
	@echo "         prog-list: show information of loaded eBPF programs named marker."
	@echo ""
	@echo "   start-ipv4-flow: write to flowd-go's named pipe to start an IPv4 flow."
	@echo "     end-ipv4-flow: write to flowd-go's named pipe to end an IPv4 flow."
	@echo "   start-ipv6-flow: write to flowd-go's named pipe to start an IPv6 flow."
	@echo "     end-ipv6-flow: write to flowd-go's named pipe to end an IPv6 flow."
	@echo ""
	@echo "  start-dummy-flow: send an HTTP GET request to flowd-go's API to start an IPv6 flow."
	@echo "    end-dummy-flow: send an HTTP GET request to flowd-go's API to end an IPv6 flow."
	@echo "          api-flow: send an HTTP POST request to flowd-go's API with a JSON payload"
	@echo "                    describing the flow ID to send downstream to the backends. The"
	@echo "                    path to the JSON file describing the flow ID can be passed through"
	@echo "                    the SPEC option. The default SPEC is plugins/api/testdata/start.json"
	@echo ""
	@echo "      docker-start: start the development container in the background. You can pass the"
	@echo "                    additional argument FLAVOUR with a value of one of {dev,test,release}"
	@echo "                    to specify the image to run. By default FLAVOUR is set to dev. Passing"
	@echo "                    the argument looks like: 'make docker-start FLAVOUR=test'."
	@echo "      docker-shell: open a shell into the development container. Note it must be"
	@echo "                    started first with the 'docker-start' target."
	@echo "       docker-stop: stop the development container."
	@echo "      docker-build: build the development container."
	@echo "       docker-push: push the built image to GitHub's registry."
	@echo ""
	@echo "     firefly-start: send a firefly as defined in plugins/fireflyp/testdata/start_firefly.json."
	@echo "       firefly-end: send a firefly as defined in plugins/fireflyp/testdata/end_firefly.json."
	@echo "    firefly-listen: listen for outgoing fireflies on port 10515."
	@echo ""
	@echo "             clean: delete everything defined as rubbish."

# Simply build flowd-go
build: $(SOURCES) ebpf-progs
	@mkdir -p bin
	$(ENV_FLAGS) $(GOC) build $(CFLAGS) -o $(BIN_DIR)/$(BIN_NAME) $(MAIN_PACKAGE)

# We'll only compile the eBPF program if we're on Linux
ifeq ($(OS),Linux)
# Recursively build the eBPF program. Be sure to check
# https://www.gnu.org/software/make/manual/html_node/Recursion.html
ebpf-progs:
	$(MAKE) -C $(EBPF_BACKEND_PROGS_PATH)
	$(MAKE) -C $(EBPF_ENRICHMENT_PROGS_PATH)
else
# Just provide a stub it we're not on Linux!
ebpf-progs:
endif

# Include Makefiles with additional targets automating stuff.
# Check https://www.gnu.org/software/make/manual/html_node/Include.html
ifndef BUILDING_RPM
include mk/*.mk
endif

.PHONY: clean
clean:
	$(MAKE) -C $(EBPF_BACKEND_PROGS_PATH) clean
	$(MAKE) -C $(EBPF_ENRICHMENT_PROGS_PATH) clean
	@rm -rf $(TRASH)
