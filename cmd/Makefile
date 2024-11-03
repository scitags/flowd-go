# *+++++++++++++++++*************************************************** #
# Be sure to check what tracee (https://github.com/aquasecurity/tracee) #
# does for compiling. It basically compiles libbpf itself! Just clone   #
# and compile it to get the commands used in the process.               #
# *+++++++++++++++++*************************************************** #

# The Go compiler to use
GOC = go

# Configure this release's verision and commit
# VERSION = $(shell git describe --tags --abbrev=0)
COMMIT = $(shell git rev-parse --short HEAD)

BIN_DIR = ./bin

SOURCES = $(wildcard *.go)
TRASH   = $(BIN_DIR)/* cmd

# The `-ldflags` option lets us define global variables at compile time!
# Check https://stackoverflow.com/questions/11354518/application-auto-build-versioning

darwin:
	$(GOC) build -tags ebpf -ldflags "-X main.builtCommit=$(COMMIT)"

# TODOs:
#     Maybe we need the -L? Check it!
#     CGO_LDFLAGS="-L/usr/lib64/libbpf.a"

# NOTE:
#     CGO_ENABLED="1" is not needed, but we'd rather be explicit...
build: $(SOURCES)
	@echo "Building commit $(COMMIT)"
	CGO_CFLAGS="-I/usr/include/bpf"       \
		CGO_LDFLAGS="/usr/lib64/libbpf.a" \
		CC="clang"                        \
		CGO_ENABLED="1"                   \
		$(GOC) build -tags ebpf -ldflags "-X main.builtCommit=$(COMMIT)"

# Check automatic make variables over at
#    https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
mark.bpf.o: mark.bpf.c
	clang -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c $^ -o $@

.PHONY: clean tc-show tc-clean start-np-flow end-np-flow

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

start-np-flow:
	@echo "start tcp 192.168.0.1 2345 127.0.0.1 5777 1 2" > np

end-np-flow:
	@echo "end tcp 192.168.0.1 2345 127.0.0.1 5777 1 2" > np

clean:
	@rm -rf $(TRASH)
