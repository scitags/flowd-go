PROG_NAME := watcher

define targetTemplate
$(PROG_NAME).bpf.o: $(DEPS)
	$(CC) $(CFLAGS)                $(PROG_NAME).bpf.c -o $$@

$(PROG_NAME)-dbg.bpf.o: $(DEPS)
	$(CC) $(CFLAGS) -D FLOWD_DEBUG $(PROG_NAME).bpf.c -o $$@
endef

all: $(PROG_NAME).bpf.o $(PROG_NAME)-dbg.bpf.o

$(eval $(call targetTemplate))

.PHONY: load
load: $(PROG_NAME)-dbg.bpf.o
	sudo bpftool prog load $< /sys/fs/bpf/$(PROG_NAME)
	sudo bpftool cgroup attach /sys/fs/cgroup$$(cat /proc/$$$$/cgroup | cut -d ':' -f 3) sock_ops pinned /sys/fs/bpf/$(PROG_NAME)

.PHONY: unload
unload:
	sudo bpftool cgroup detach /sys/fs/cgroup$$(cat /proc/$$$$/cgroup | cut -d ':' -f 3) sock_ops pinned /sys/fs/bpf/$(PROG_NAME)
	sudo rm -rf /sys/fs/bpf/$(PROG_NAME)

.PHONY: list
list:
	sudo bpftool prog list name watcher

.PHONY: trace
trace:
	sudo bpftool prog tracelog

.PHONY: clean
clean:
	@rm -rf $(TRASH)
