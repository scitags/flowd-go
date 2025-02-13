# This Makefile provides several PHONY targets for dealing with the aftermath
# of running an ill-behaved ebpf program.

# Check https://qmonnet.github.io/whirl-offload/2020/04/11/tc-bpf-direct-action/
# for a great discusson on tc introspection!
.PHONY: tc-show
tc-show:
	@echo QDisc:
	@sudo tc qdisc show dev lo
	@echo Ingress filters:
	@sudo tc filter show dev lo ingress
	@echo Egress filters:
	@sudo tc filter show dev lo egress

.PHONY: tc-clean
tc-clean:
	@sudo tc qdisc del dev lo clsact

.PHONY: ebpf-trace
ebpf-trace:
	@sudo cat /sys/kernel/debug/tracing/trace_pipe

.PHONY: prog-list
prog-list:
	@sudo bpftool prog list name marker
