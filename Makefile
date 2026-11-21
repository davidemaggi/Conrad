.PHONY: all web build test clean dev

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

all: build

web:
	cd web && npm ci && npm run build

build: web
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/conrad ./cmd/conrad

test:
	go test ./...
	cd web && npm test

dev:
	cd web && npm run dev

clean:
	rm -rf bin
	find internal/web/dist -mindepth 1 ! -name .gitkeep -exec rm -rf {} +
