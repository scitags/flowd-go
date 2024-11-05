# What compiler to use?
CC=clang

# Compiler flgas we'll use no matter what
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c

# Compiler flags that'll include if the DEBUG variable is defined
# when invoking make. To trigger this one need just call:
#   $ make DEBUG=yes
# The actual value is not important, as long as it's something the
# variable will be deifned, which is what we care about.
ifdef DEBUG
CFLAGS := $(CFLAGS) -DGLOWD_DEBUG
endif

# The files to eliminate when cleaning up
TRASH := marker.bpf.o

# Check automatic make variables over at
#    https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
marker.bpf.o: marker.bpf.c vmlinux.h
	$(CC) $(CFLAGS) $< -o $@

# Generate the kernel headers
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

.PHONY: clean

clean:
	@rm -rf $(TRASH)
