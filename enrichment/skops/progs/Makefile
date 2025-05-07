# What compiler to use?
CC := clang

# Compiler flgas we'll use no matter what
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c

# The files to eliminate when cleaning up
TRASH := *.o vmlinux.h .cache

sk_ops.bpf.o: *.bpf.c vmlinux.h
	$(CC) $(CFLAGS) sk_ops.bpf.c -o $@

# Generate the kernel headers
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Let us remember how to inspect an object in a week's time!
.PHONY: objdump
objdump: sk_ops.bpf.o
	objdump --syms $<

.PHONY: load
load: sk_ops.bpf.o
	sudo bpftool prog load sk_ops.bpf.o /sys/fs/bpf/sk_ops
	sudo bpftool cgroup attach /sys/fs/cgroup/user.slice/user-1000.slice/session-1152.scope sock_ops pinned /sys/fs/bpf/sk_ops

.PHONY: unload
unload:
	sudo bpftool cgroup detach /sys/fs/cgroup/user.slice/user-1000.slice/session-1152.scope sock_ops pinned /sys/fs/bpf/sk_ops
	sudo rm -rf /sys/fs/bpf/sck_ops

.PHONY: list
list:
	sudo bpftool prog list name connTracker

.PHONY: trace
trace:
	sudo bpftool prog tracelog

.PHONY: clean
clean:
	@rm -rf $(TRASH)
