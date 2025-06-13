gOC := go

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

CGO_CFLAGS="-I/usr/include/bpf" CGO_LDFLAGS="/usr/lib64/libbpf.a" CC="clang" CGO_ENABLED="1" go test -run Attach -c -o foo

test: $(SOURCES) ebpf-progs
	$(ENV_FLAGS) $(GOC) test -c -o test
	@echo "Filter tests to run with ./test -test.run regExp (see ./test -help)"

ebpf-progs:
	$(MAKE) -C progs

.PHONY: integration-test
integration-test:
	@sudo DST_IP=::1 CONG_ALG=cubic RUNTIME_SEC=60 ./test -test.run TestGatherFirefly
