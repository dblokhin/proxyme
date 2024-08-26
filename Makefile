GO ?= go
GOBUILD = $(GO) build
GOCLEAN = $(GO) clean
GOTEST = $(GO) test
GOGET = $(GO) get
BINARY_NAME = proxyme
GOLANGCI_LINT_VERSION := v1.60.2
BIN_DIR := $(shell go env GOPATH)/bin

test:
	$(GOTEST) -cover -count=1 ./...

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	$(BIN_DIR)/golangci-lint run ./...

godoc:
	$(BIN_DIR)/godoc -http :6060

deps:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(BIN_DIR) $(GOLANGCI_LINT_VERSION)
	@go install -v golang.org/x/tools/cmd/godoc@latest

.PHONY: test fmt lint deps
