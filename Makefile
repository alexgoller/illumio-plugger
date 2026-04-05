BINARY := plugger
BUILD_DIR := bin
MODULE := github.com/illumio/plugger
VERSION ?= dev
LDFLAGS := -ldflags "-X $(MODULE)/internal/cli.Version=$(VERSION)"

.PHONY: build test lint clean install

build:
	go build $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY) ./cmd/plugger

test:
	go test ./...

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)

install: build
	cp $(BUILD_DIR)/$(BINARY) $(GOPATH)/bin/$(BINARY)
