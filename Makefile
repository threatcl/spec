GO_CMD?=go
VERSION?=$(shell grep 'var Version' version.go | sed 's/.*"\(.*\)".*/\1/')

default: help

vet: ## Run go vet
	$(GO_CMD) vet ./...

test: ## Run go test
	$(GO_CMD) test ./...

build: ## Build with version information
	$(GO_CMD) build -ldflags "-X github.com/threatcl/spec.Version=$(VERSION)"

bump-version: ## Bump version (usage: make bump-version OLD=0.2.1 NEW=0.2.2)
	@if [ -z "$(OLD)" ] || [ -z "$(NEW)" ]; then \
		echo "Usage: make bump-version OLD=x.y.z NEW=x.y.z"; \
		echo "Example: make bump-version OLD=0.2.1 NEW=0.2.2"; \
		exit 1; \
	fi
	$(GO_CMD) run scripts/bump_version.go -old $(OLD) -new $(NEW)

help: ## Output make targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

.PHONY: vet test build bump-version help
