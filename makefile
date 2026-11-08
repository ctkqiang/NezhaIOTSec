APP     := nezhaiot
BIN_DIR := bin
BIN     := $(BIN_DIR)/$(APP)
PKG     := ./cmd/nezha_iot
GO      ?= go
LDFLAGS := -s -w
TARGETS := linux/amd64 linux/arm64 darwin/arm64

.DEFAULT_GOAL := build

.PHONY: build run test vet fmt tidy check cross android clean help

build:
	@echo "Building $(APP)..."
	@mkdir -p $(BIN_DIR)
	$(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

run: build 
	@echo "Running $(APP)..."
	./$(BIN)

test: 
	@echo "Running unit tests..."
	$(GO) test ./...

vet: 
	@echo "Running go vet..."
	$(GO) vet ./...

fmt: 
	@echo "Formatting code..."
		gofmt -l -w .

tidy: 
	$(GO) mod tidy

check: fmt vet test  

cross:
	@mkdir -p $(BIN_DIR)
	@for target in $(TARGETS); do \
		os=$${target%/*}; \
		arch=$${target#*/}; \
		echo "  -> $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(BIN_DIR)/$(APP)-$$os-$$arch $(PKG) || exit 1; \
	done

android:  ## static arm64 binary for unrooted Termux (CGO off, no glibc)
	@echo "Building $(APP) for android/arm64..."
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" \
		-o $(BIN_DIR)/$(APP)-android-arm64 $(PKG)

clean:  ## remove build artifacts
	$(GO) clean
	rm -rf $(BIN_DIR)

help:  ## list available targets
	@grep -E '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-8s\033[0m %s\n", $$1, $$2}'
