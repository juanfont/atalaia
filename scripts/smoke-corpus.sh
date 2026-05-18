#!/usr/bin/env bash
# Run the integration corpus against a real LLM. Builds atalaia,
# spins it up on a non-default port, then runs the build-tagged
# integration test which POSTs every fixture and grades agreement.
#
# Usage:
#   CONFIG=internal-docs/smoke.yaml ./scripts/smoke-corpus.sh
#   ./scripts/smoke-corpus.sh /path/to/atalaia.yaml
#
# Override INTEGRATION_MIN_AGREEMENT (default 0.8) to tighten or
# loosen the per-corpus pass threshold. Observed on Gemma 4 E4B
# with tool calling: 6/6 consistently across runs (0 gap-fills).
# Smaller models warrant a lower floor.

set -euo pipefail

CONFIG="${1:-${CONFIG:-internal-docs/smoke.yaml}}"
LISTEN="${LISTEN:-127.0.0.1:18080}"
METRICS="${METRICS:-127.0.0.1:19090}"

if [[ ! -f $CONFIG ]]; then
    echo "smoke-corpus: missing config: $CONFIG" >&2
    exit 1
fi

cleanup() {
    if [[ -n "${ATALAIA_PID:-}" ]]; then
        kill -TERM "$ATALAIA_PID" 2>/dev/null || true
        wait "$ATALAIA_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "corpus: building"
go build -o atalaia ./cmd/atalaia

echo "corpus: starting server on $LISTEN"
ATALAIA_SERVER_LISTEN=$LISTEN \
ATALAIA_OBSERVABILITY_METRICS_ADDR=$METRICS \
    ./atalaia serve -c "$CONFIG" >/tmp/atalaia-corpus.log 2>&1 &
ATALAIA_PID=$!

for i in {1..20}; do
    if curl -sSf "http://${LISTEN}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if ! curl -sSf "http://${LISTEN}/healthz" >/dev/null 2>&1; then
    echo "corpus: server did not come up" >&2
    tail -20 /tmp/atalaia-corpus.log >&2
    exit 1
fi

echo "corpus: running test suite"
ATALAIA_INTEGRATION_URL="http://${LISTEN}" \
INTEGRATION_MIN_AGREEMENT="${INTEGRATION_MIN_AGREEMENT:-0.8}" \
    go test -tags=integration -count=1 -timeout 600s -v ./internal/integration
