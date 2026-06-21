VERSION ?= dev
GO_LDFLAGS = -X github.com/juanfont/atalaia.Version=$(VERSION)

# Pinned detector versions. Bump deliberately; do not float.
# Verify upstream release notes before changing.
TRUFFLEHOG_VERSION ?= 3.90.1
KINGFISHER_VERSION ?= 1.27.0

PREFIX ?= /usr/local

.PHONY: build test test-integration smoke smoke-corpus smoke-corpus-deep vet fmt tidy install-detectors install-trufflehog install-kingfisher clean

build:
	go build -ldflags '$(GO_LDFLAGS)' -o atalaia ./cmd/atalaia

test:
	go test ./...

# Mirror the CI integration job locally. Subprocess detector tests
# t.Skip when the binary isn't on PATH, so this target checks first
# and points at `make install-trufflehog` if it's missing.
test-integration:
	@command -v trufflehog >/dev/null || { \
	    echo "trufflehog not on PATH. run: make install-trufflehog"; \
	    exit 1; \
	}
	go test -count=1 -timeout 180s ./internal/detector

# End-to-end smoke against a real LLM. Override CONFIG to point at
# your own config file. Defaults to internal-docs/smoke.yaml.
smoke:
	CONFIG=$(CONFIG) ./scripts/smoke.sh

# Full integration corpus against a real LLM. Builds atalaia,
# spins it up, runs every fixture under internal/integration/testdata
# and grades overall agreement. Override INTEGRATION_MIN_AGREEMENT
# to tune the pass threshold (default 0.75).
smoke-corpus:
	CONFIG=$(CONFIG) ./scripts/smoke-corpus.sh

# Deep corpus: scan every fixture INTEGRATION_REPEAT times and gate on
# per-fixture agreement, surfacing the model's residual non-determinism
# (the kind that leaks the odd false positive) instead of sampling once.
# Slower; for nightly / pre-release, not every commit.
smoke-corpus-deep:
	INTEGRATION_REPEAT=$(or $(INTEGRATION_REPEAT),20) CONFIG=$(CONFIG) ./scripts/smoke-corpus.sh

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
