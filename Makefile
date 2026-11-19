# Common developer tasks. Integration tests need a PostgreSQL server:
#   export NODDANAS_TEST_DATABASE_URL=postgres://user:pass@localhost:5432/noddanas_test?sslmode=disable
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

.PHONY: build test lint vuln gosec docker

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(VERSION)" -o bin/noddanas ./cmd/noddanas

test:
	go test -race -count=1 ./...

lint:
	test -z "$$(gofmt -l .)"
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck@v0.8.2 ./...

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...

gosec:
	go run github.com/securego/gosec/v2/cmd/gosec@v2.30.0 -exclude-dir=internal/testutil ./...

docker:
	docker build --build-arg VERSION=$(VERSION) -t noddanas:$(VERSION) .
