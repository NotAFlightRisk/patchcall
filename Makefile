VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build run test lint site clean

build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o patchcall .

run:
	go run . --once

test:
	go test ./...

lint:
	go vet ./...
	test -z "$$(gofmt -l .)" || (gofmt -l . && exit 1)

site:
	./scripts/site.sh

clean:
	rm -rf patchcall dist site
