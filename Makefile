GO_CMD?=go

default: help

vet: ## Run go vet
	$(GO_CMD) vet ./...

test: ## Run go test
	$(GO_CMD) test ./...

help: ## Output make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: vet test help
