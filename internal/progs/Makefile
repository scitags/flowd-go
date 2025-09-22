# What compiler to use?
export CC := clang

# Compiler flags we'll use no matter what:
#   -g: 
export CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -I .. -c

# The files to eliminate when cleaning up
export TRASH := *.o vmlinux.h .cache

# Dependencies of each eBPF program
export DEPS := *.bpf.c *.bpf.h ../vmlinux.h

# Simply make target all depend on all the programs
all: vmlinux.h
	$(MAKE) -C marker
	$(MAKE) -C skops

# Generate the kernel headers
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean
clean:
	$(MAKE) -C marker clean
	$(MAKE) -C skops clean
	@rm -rf $(TRASH)
