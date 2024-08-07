GO ?= go
GOBUILD = $(GO) build
GOCLEAN = $(GO) clean
GOTEST = $(GO) test
GOGET = $(GO) get
BINARY_NAME = proxyme
GOLANGCI_LINT_VERSION := v1.59.1
BIN_DIR := $(shell go env GOPATH)/bin

build:
	$(GOBUILD) -o $(BINARY_NAME) -v

run:
	$(GOBUILD) -o $(BINARY_NAME) -v . && ./$(BINARY_NAME)

test:
	$(GOTEST) -v ./...

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)

fmt:
	$(GO) fmt ./...

lint:
	$(GO) vet ./...
	$(BIN_DIR)/golangci-lint run ./...

deps:
	@curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(BIN_DIR) $(GOLANGCI_LINT_VERSION)

docker-build:
	docker build -t $(BINARY_NAME) .

docker-run:
	docker run --rm -it $(BINARY_NAME)

.PHONY: build clean test run fmt lint deps docker-build docker-run
