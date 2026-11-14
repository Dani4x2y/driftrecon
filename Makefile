BINARY  := driftrecon
PKG     := github.com/Dani4x2y/driftrecon
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X $(PKG)/internal/version.tag=$(VERSION)

.PHONY: build test vet lint fmt clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/driftrecon

test:
	go test ./...

vet:
	go vet ./...

lint:
	go run honnef.co/go/tools/cmd/staticcheck@latest ./...

fmt:
	gofmt -l -w .

clean:
	rm -f $(BINARY) $(BINARY).exe
