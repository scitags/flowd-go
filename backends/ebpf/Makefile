# What compiler to use?
CC=clang

# Compiler flgas we'll use no matter what
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c

# The files to eliminate when cleaning up
TRASH := *.o vmlinux.h

all: marker.bpf.o marker-dbg.bpf.o

# Check automatic make variables over at
#    https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
marker.bpf.o: marker.bpf.c vmlinux.h
	$(CC) $(CFLAGS) $< -o $@

marker-dbg.bpf.o: marker.bpf.c vmlinux.h
	$(CC) $(CFLAGS) -DGLOWD_DEBUG $< -o $@

# Generate the kernel headers
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: objdump
objdump: marker.bpf.o
	objdump --syms $<

.PHONY: clean
clean:
	@rm -rf $(TRASH)
