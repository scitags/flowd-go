# This Makefile provides several PHONY targets for creating/deleting flows
# by interacting with the API plugin.

# The path to a JSON file describing the flow to send embedded in the POST to
# flowd-go's API.
SPEC ?= ./plugins/api/testdata/start.json

.PHONY: start-dummy-flow
start-dummy-flow:
	curl http://localhost:7777/dummy/start

.PHONY: end-dummy-flow
end-dummy-flow:
	curl http://localhost:7777/dummy/end

.PHONY: api-flow
api-flow:
	curl -X POST http://localhost:7777/flow \
		-H 'Content-Type: application/json' \
		--data "@$(SPEC)"
