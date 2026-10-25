BINARY ?= sentinel-net
VERSION ?= 1.0.0
LDFLAGS := -s -w -X github.com/abiyeenzo/sentinel-net/internal/cli.Version=$(VERSION)

.PHONY: all build build-windows test vet clean

all: vet test build

vet:
	go vet ./...

test:
	go test -v -race ./...

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY) ./cmd/sentinel-net

build-windows:
	mkdir -p dist
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/$(BINARY).exe ./cmd/sentinel-net

clean:
	rm -rf dist build coverage.out
