.DEFAULT_GOAL:=help
SHELL:=/bin/bash

BIN = grant
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +%Y-%m-%dT%H:%M:%SZ
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif

GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

## Go related variables
## TODO LD_FLAGS should be set by the build system
LDFLAGS = ""
SRCS = $(shell find cmd -iname "*.go")

.PHONY: clean grant help
grant: $(SRCS) ## Build the grant binary
		go build -buildmode=pie -ldflags $(LDFLAGS) -o $(BIN) ./cmd/grant
	CGO_ENABLED=0 go build -trimpath -ldflags $(LDFLAGS) -o $@ ./cmd/grant

clean: ## clean the build artifacts
	rm -rf $(BIN)

help: ## Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ {\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		}' $(MAKEFILE_LIST) | sort
