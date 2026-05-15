#!/usr/bin/env bash
# End-to-end smoke against a real LLM. Builds atalaia, probes the
# configured endpoint, starts the server, POSTs a fixture diff,
# verifies the response shape, then tears the server down.
#
# Usage:
#   CONFIG=internal-docs/smoke.yaml ./scripts/smoke.sh
#   ./scripts/smoke.sh /path/to/atalaia.yaml
#
# The config must point llm.endpoint at a reachable LLM. Server.listen
# is overridden to 127.0.0.1:18080 so this won't fight with a running
# instance.

set -euo pipefail

CONFIG="${1:-${CONFIG:-internal-docs/smoke.yaml}}"
DIFF_FIXTURE="${DIFF_FIXTURE:-internal/api/testdata/sample.diff}"
SMOKE_LISTEN="${SMOKE_LISTEN:-127.0.0.1:18080}"
SMOKE_METRICS="${SMOKE_METRICS:-127.0.0.1:19090}"

if [[ ! -f $CONFIG ]]; then
    echo "smoke: config file not found: $CONFIG" >&2
    echo "  set CONFIG=path/to/atalaia.yaml or pass it as \$1" >&2
    exit 1
fi
if [[ ! -f $DIFF_FIXTURE ]]; then
    echo "smoke: diff fixture not found: $DIFF_FIXTURE" >&2
    exit 1
fi

cleanup() {
    if [[ -n "${ATALAIA_PID:-}" ]]; then
        kill -TERM "$ATALAIA_PID" 2>/dev/null || true
        wait "$ATALAIA_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

echo "smoke: config=$CONFIG"
echo "smoke: 1/4 building atalaia"
go build -o atalaia ./cmd/atalaia

echo "smoke: 2/4 probing LLM"
./atalaia probe -c "$CONFIG" >/dev/null

echo "smoke: 3/4 starting server on $SMOKE_LISTEN"
ATALAIA_SERVER_LISTEN=$SMOKE_LISTEN \
ATALAIA_OBSERVABILITY_METRICS_ADDR=$SMOKE_METRICS \
    ./atalaia serve -c "$CONFIG" >/tmp/atalaia-smoke.log 2>&1 &
ATALAIA_PID=$!

# Wait up to 10s for the server to be listening.
for i in {1..20}; do
    if curl -sSf "http://${SMOKE_LISTEN}/healthz" >/dev/null 2>&1; then
        break
    fi
    sleep 0.5
done
if ! curl -sSf "http://${SMOKE_LISTEN}/healthz" >/dev/null 2>&1; then
    echo "smoke: server did not come up; last 20 log lines:" >&2
    tail -20 /tmp/atalaia-smoke.log >&2
    exit 1
fi

echo "smoke: 4/4 POST /check"
RESP=$(curl -sSf -X POST \
    -H 'content-type: text/x-diff' \
    --data-binary @"$DIFF_FIXTURE" \
    "http://${SMOKE_LISTEN}/check")

# Minimal shape checks. We don't assert on the verdict value: the
# LLM is allowed to disagree. We do assert that the pipeline ran.
echo "$RESP" | python3 -c '
import json, sys
r = json.loads(sys.stdin.read())
assert r["request_id"], "missing request_id"
assert isinstance(r["verdicts"], list), "verdicts not a list"
assert len(r["verdicts"]) >= 1, "expected at least one verdict"
v = r["verdicts"][0]
assert v["match_preview"] and v["match_preview"] != "AKIA1234ABCDEFGHIJKL", \
    "match_preview missing or leaked raw match"
assert r["stats"]["llm_invoked"] is True, "stats.llm_invoked != true"
assert r["stats"]["after_dedup"] >= 1
print("smoke: OK", json.dumps({"verdict": v["verdict"], "llm_ms": r["stats"]["llm_latency_ms"]}))
'
