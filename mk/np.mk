# This Makefile provides several PHONY targets automating the creation/deletion
# of flows through the named pipe (np) plugin

.PHONY: start-ipv4-flow
start-ipv4-flow:
	@sudo bash -c 'echo "start tcp 192.168.0.1 2345 127.0.0.1 5777 1 2" > np'

.PHONY: end-ipv4-flow
end-ipv4-flow:
	@sudo bash -c 'echo "end tcp   192.168.0.1 2345 127.0.0.1 5777 1 2" > np'

.PHONY: start-ipv6-flow
start-ipv6-flow:
	@sudo bash -c 'echo "start tcp         ::1 2345       ::1 5777 1 2" > np'

.PHONY: end-ipv6-flow
end-ipv6-flow:
	@sudo bash -c 'echo "end tcp           ::1 2345       ::1 5777 1 2" > np'
