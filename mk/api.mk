# This Makefile provides serveral PHONY targets for creating/deleting flows
# by interacting with the API plugin

.PHONY: start-dummy-flow
start-dummy-flow:
	curl http://localhost:7777/dummy/start

.PHONY: end-dummy-flow
end-dummy-flow:
	curl http://localhost:7777/dummy/end
