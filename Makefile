# The Go compiler to use
GOC = go

# TODOs:
#   - Find a clean way to propagate the git-based version to the SPEC file.
#   - Properly pick up Go source files (i.e. don't use $(wildcard *.go))

# Please note this environment variable will only be defined when running
# the %build scriptlet of a SPEC file during the building of RPM packages.
ifdef RPM_PACKAGE_NAME
    $(info running in an RPM context!)
    VERSION = $(RPM_PACKAGE_VERSION)
    COMMIT = $(shell cat commit)

    # Disable VCS stamping when building the RPMs: the .git directory won't be there!
    CFLAGS := $(CFLAGS) -buildvcs=false
else
    VERSION = $(shell git describe --tags --abbrev=0)
    COMMIT = $(shell git rev-parse --short HEAD)
endif

# Define the value of version-related global variables
CFLAGS := $(CFLAGS) -ldflags "-X main.builtCommit=$(COMMIT) -X main.baseVersion=$(VERSION)"
CFLAGS := $(CFLAGS) -ldflags "-X github.com/scitags/flowd-go/types.SYSLOG_APP_NAME=flowd-go-$(VERSION)"

# If adding support for eBPF programs pull in the necessary loaders and helpers.
ifndef NO_EBPF
    CFLAGS := $(CFLAGS) -tags ebpf
endif

# Prevent natively-compiled binaries from enabling CGO by default. Otherwise, the
# C runtime (i.e. libc) and some other libraries will be symbolically linked. For
# more information see https://pkg.go.dev/cmd/cgo
ENV_FLAGS := CGO_ENABLED=0

# Adjust the target architecture based on the TARGET_ARCH variable.
# As this variable is populated by the {%_target} macro it can
# change with the rpmbuild version, so we're handling several
# cases we've run into in the wild
TARGET_ARCH ?= x86_64
ifeq ($(TARGET_ARCH),x86_64)
    ENV_FLAGS := $(ENV_FLAGS) GOARCH=amd64
else ifeq ($(TARGET_ARCH),x86_64-linux)
    ENV_FLAGS := $(ENV_FLAGS) GOARCH=amd64
else ifeq ($(TARGET_ARCH),aarch64)
    ENV_FLAGS := $(ENV_FLAGS) GOARCH=arm64
else ifeq ($(TARGET_ARCH),aarch64-linux)
    ENV_FLAGS := $(ENV_FLAGS) GOARCH=arm64
endif

# Extract reused paths
BIN_DIR        := ./bin
EBPF_PROG_PATH := internal/progs

# Make 'help' the default target
ifndef RPM_PACKAGE_NAME
    include mk/help
endif

# Simply build flowd-go
build: $(wildcard *.go) ebpf-progs generate
	@mkdir -p bin
	@echo "TARGET_ARCH: $(TARGET_ARCH)"
	$(ENV_FLAGS) $(GOC) build $(CFLAGS) -o $(BIN_DIR)/flowd-go ./cmd

# We're leveraging golang.org/x/tools/cmd/stringer
.PHONY: generate
generate:
	$(GOC) generate ./...

# We'll only compile the eBPF programs if explicitly told to do so
ifndef NO_EBPF
# Recursively build eBPF programs. Check https://www.gnu.org/software/make/manual/html_node/Recursion.html
ebpf-progs:
	$(MAKE) -C $(EBPF_PROG_PATH)
else
ebpf-progs:
endif

# Include Makefiles with additional targets automating stuff.
# Check https://www.gnu.org/software/make/manual/html_node/Include.html
ifndef RPM_PACKAGE_NAME
    include mk/*.mk
endif

.PHONY: clean
clean:
	$(MAKE) -C $(EBPF_PROG_PATH) clean
	@rm -rf $(BIN_DIR)/* rpms/*.gz rpms/*.rpm *.tar.gz commit vendor
