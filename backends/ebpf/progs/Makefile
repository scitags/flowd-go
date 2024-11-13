# What compiler to use?
CC := clang

# Compiler flgas we'll use no matter what
CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_x86_64 -I . -c

# The files to eliminate when cleaning up
TRASH := *.o vmlinux.h

# Just increase seq(1)'s upper limit as new exercise sheets are added!
# This is the only variable we have to modify when adding new targets.
# Note each item will be appended to 'marker-' so as to generate the
# output programs.
PROG_NAMES := flow-label hbh-header hbh-do-headers

# Derive the contants the program depends on for conditionally compilating
# it. We simple add the GLOWD_ prefix and translate each element of PROG_NAMES
# with tr(1) so that we transform '-' to '_' and make lower case letters
# uppercase. We do realy on a shell for that, but echo and tr are usually there!
PROG_DEFS := $(addprefix GLOWD_, $(shell echo $(PROG_NAMES) | tr 'a-z-' 'A-Z_'))

# We use seq(1) to generate the indices to then index both PROG_NAMES and
# PROG_DEFS. Like before, seq(1) should be widely available...
INDICES := $(shell seq $(words $(PROG_NAMES)))

# Define the temaplate for dynamically generating the targets. Both $(1) and $(2)
# evaluate to whatever we pass to $(call ...) later on. We'll compile both a
# program without debugging output and another one with debugging output.
# Check:
#   https://www.gnu.org/software/make/manual/html_node/Multi_002dLine.html!
#   https://www.gnu.org/software/make/manual/html_node/Automatic-Variables.html
define targetTemplate
marker-$(1).bpf.o: marker.bpf.c vmlinux.h
	$(CC) $(CFLAGS) -D $(2)                $$< -o $$@

marker-$(1)-dbg.bpf.o: marker.bpf.c vmlinux.h
	$(CC) $(CFLAGS) -D $(2) -D GLOWD_DEBUG $$< -o $$@

endef

# Just check it's working. Simply uncomment the line below to get a glimose into what
# the actual dynamic targets are!
# $(foreach i,$(INDICES),$(info $(call targetTemplate,$(word $(i),$(PROG_NAMES)),$(word $(i),$(PROG_DEFS)))))

# Simply make target all depend on all the programs
all: $(foreach progName,$(PROG_NAMES),marker-$(progName).bpf.o marker-$(progName)-dbg.bpf.o)

# Generate the dynamic targets. This must be done AFTER defining the all target as
# othwerwise the default target becomes the first dynamic target. The idea for getting
# this to work is to iterate over the INDICES variable and simply index the PROG_NAMES
# and PROG_DEFS thanks to (abusing) the $(word ...) function.
# Check:
#   https://www.gnu.org/software/make/manual/make.html#Foreach-Function
#   https://www.gnu.org/software/make/manual/make.html#Text-Functions
$(foreach i,$(INDICES),$(eval $(call targetTemplate,$(word $(i),$(PROG_NAMES)),$(word $(i),$(PROG_DEFS)))))

# Generate the kernel headers
vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Let us remember how to inspect an object in a week's time!
.PHONY: objdump
objdump: marker-flow-label.bpf.o
	objdump --syms $<

.PHONY: clean
clean:
	@rm -rf $(TRASH)
