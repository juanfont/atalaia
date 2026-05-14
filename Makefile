VERSION ?= dev
GO_LDFLAGS = -X github.com/juanfont/atalaia.Version=$(VERSION)

# Pinned detector versions. Bump deliberately; do not float.
# Verify upstream release notes before changing.
TRUFFLEHOG_VERSION ?= 3.90.1
KINGFISHER_VERSION ?= 1.27.0

PREFIX ?= /usr/local

.PHONY: build test vet fmt tidy install-detectors install-trufflehog install-kingfisher clean

build:
	go build -ldflags '$(GO_LDFLAGS)' -o atalaia ./cmd/atalaia

test:
	go test ./...

vet:
	go vet ./...

fmt:
	gofmt -l .

tidy:
	go mod tidy

install-detectors: install-trufflehog install-kingfisher

# Trufflehog is AGPL-3.0; it is installed as a binary and invoked as a
# subprocess. Atalaia must never import trufflehog as a Go module.
install-trufflehog:
	curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
		| sh -s -- -b $(PREFIX)/bin v$(TRUFFLEHOG_VERSION)

# Kingfisher ships per-target binaries from its GitHub releases.
install-kingfisher:
	curl -sSfL https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install.sh \
		| sh -s -- -b $(PREFIX)/bin v$(KINGFISHER_VERSION)

clean:
	rm -f atalaia
