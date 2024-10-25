# What compiler to use?
CC=clang

TRASH := marker.bpf.o

# Check automatic make variables over at
#    https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
marker.bpf.o: marker.bpf.c vmlinux.h
	$(CC) -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c $< -o $@

# Generate the kernel headers
vmlinux.h:
	 bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean

clean:
	@rm -rf $(TRASH)
