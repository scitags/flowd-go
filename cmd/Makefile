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

SOURCES = $(wildcard *.go)
TRASH   = $(BIN_DIR)/* cmd

# Default compilation flags.
# The `-ldflags` option lets us define global variables at compile time!
# Check https://stackoverflow.com/questions/11354518/application-auto-build-versioning
CFLAGS := -tags ebpf -ldflags "-X main.builtCommit=$(COMMIT)" -o $(BIN_DIR)

# Adjust GOC's environment depending on what OS we're on to deal with
# all the BPF machinery. Note that when ENV_FALGS is not defined on
# Darwin everything will work as expected!
OS := $(shell uname)
ifeq ($(OS),Linux)
	ENV_FLAGS := $(ENV_FLAGS) CGO_CFLAGS="-I/usr/include/bpf"

	# Maybe we need the -L? Check it!
	ENV_FLAGS := $(ENV_FLAGS) CGO_LDFLAGS="/usr/lib64/libbpf.a"
	ENV_FLAGS := $(ENV_FLAGS) CC="$(CC)"

	# This is not really needed, but we'd rather be explicit!
	ENV_FLAGS := $(ENV_FLAGS) CGO_ENABLED="1"
endif

# Simply build the command
build: $(SOURCES)
	@mkdir -p bin
	$(ENV_FLAGS) $(GOC) build $(CFLAGS)

.PHONY: clean tc-show tc-clean start-ipv4-flow end-ipv4-flow start-ipv6-flow end-ipv6-flow \
	start-dummy-flow end-dummy-flow
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

clean:
	@rm -rf $(TRASH)
