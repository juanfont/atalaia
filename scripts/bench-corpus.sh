#!/usr/bin/env bash
# Quick latency bench: POST every corpus fixture through a running
# atalaia, collect llm_latency_ms + total_latency_ms, print
# aggregated stats. Atalaia must already be running at $ATALAIA_URL.

set -euo pipefail

ATALAIA_URL="${ATALAIA_URL:-http://127.0.0.1:8080}"
RUNS="${RUNS:-3}"

fixtures=(internal/integration/testdata/diffs/*.diff)

tmp=$(mktemp)
trap "rm -f $tmp" EXIT

for run in $(seq 1 "$RUNS"); do
    for diff in "${fixtures[@]}"; do
        name=$(basename "$diff" .diff)
        resp=$(curl -sSf -X POST \
            -H 'content-type: text/x-diff' \
            --data-binary @"$diff" \
            "$ATALAIA_URL/check")
        llm=$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stats"]["llm_latency_ms"])')
        total=$(echo "$resp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["stats"]["total_latency_ms"])')
        printf "%-22s llm=%5d ms  total=%5d ms\n" "$name" "$llm" "$total"
        echo "$llm $total $name" >> "$tmp"
    done
    echo
done

echo "--- aggregate (runs=$RUNS, fixtures=${#fixtures[@]}) ---"
python3 <<PY
rows = [l.split() for l in open("$tmp") if l.strip()]
llm = sorted(int(r[0]) for r in rows)
tot = sorted(int(r[1]) for r in rows)
def stat(name, xs):
    n = len(xs)
    median = xs[n//2]
    p95 = xs[min(n-1, int(n*0.95))]
    print(f"{name}: n={n} min={xs[0]:>5} median={median:>5} mean={sum(xs)//n:>5} p95={p95:>5} max={xs[-1]:>5} (ms)")
stat("llm  ", llm)
stat("total", tot)
PY
