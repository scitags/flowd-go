PROG_NAMES := poll transition
PROG_DEFS  := $(addprefix FLOWD_, $(shell echo $(PROG_NAMES) | tr 'a-z-' 'A-Z_'))
INDICES    := $(shell seq $(words $(PROG_NAMES)))

define targetTemplate
skops-$(1).bpf.o: $(DEPS)
	$(CC) $(CFLAGS) -D $(2)                sk_ops.bpf.c -o $$@

skops-$(1)-dbg.bpf.o: $(DEPS)
	$(CC) $(CFLAGS) -D $(2) -D FLOWD_DEBUG sk_ops.bpf.c -o $$@
endef

# Just check it's working. Simply uncomment the line below to get a glimpse into what
# the actual dynamic targets are!
# $(foreach i,$(INDICES),$(info $(call targetTemplate,$(word $(i),$(PROG_NAMES)),$(word $(i),$(PROG_DEFS)))))

# Simply make target all depend on all the programs
all: $(foreach progName,$(PROG_NAMES),skops-$(progName).bpf.o skops-$(progName)-dbg.bpf.o)

# Generate the dynamic targets. This must be done AFTER defining the all target as
# otherwise the default target becomes the first dynamic target. The idea for getting
# this to work is to iterate over the INDICES variable and simply index the PROG_NAMES
# and PROG_DEFS thanks to (abusing) the $(word ...) function.
# Check:
#   https://www.gnu.org/software/make/manual/make.html#Foreach-Function
#   https://www.gnu.org/software/make/manual/make.html#Text-Functions
$(foreach i,$(INDICES),$(eval $(call targetTemplate,$(word $(i),$(PROG_NAMES)),$(word $(i),$(PROG_DEFS)))))

# Generate a correct compile_commands.json for clangd
compile_commands.json:
	@bear -- make

# Let us remember how to inspect an object in a week's time!
.PHONY: objdump
objdump: sk_ops.bpf.o
	objdump --syms $<

.PHONY: load
load: sk_ops.bpf.o
	sudo bpftool prog load sk_ops.bpf.o /sys/fs/bpf/sk_ops
	sudo bpftool cgroup attach /sys/fs/cgroup/user.slice/user-1000.slice/session-582.scope sock_ops pinned /sys/fs/bpf/sk_ops

.PHONY: unload
unload:
	sudo bpftool cgroup detach /sys/fs/cgroup/user.slice/user-1000.slice/session-582.scope sock_ops pinned /sys/fs/bpf/sk_ops
	sudo rm -rf /sys/fs/bpf/sk_ops

.PHONY: list
list:
	sudo bpftool prog list name connTracker

.PHONY: trace
trace:
	sudo bpftool prog tracelog

.PHONY: clean
clean:
	@rm -rf $(TRASH)
