.DEFAULT_GOAL := build

BINARY := bin/headless-cognito

.PHONY: build test vet clean

build:
	mkdir -p bin
	go build -o $(BINARY) ./cmd/headless-cognito

test:
	go test ./...

vet:
	go vet ./...

clean:
	rm -rf bin
