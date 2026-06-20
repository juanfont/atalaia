# Atalaia API

The contract callers integrate against. Everything Atalaia exposes is
HTTP. There are four endpoints. The interesting one is `POST /check`.

Go consumers can skip the schema-redefining step: the wire types live
in [`github.com/juanfont/atalaia/apitypes`](../apitypes), a
stdlib-only public package. `import` it and decode `/check` responses
into `apitypes.CheckResponse` directly.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| POST | `/check` | Adjudicate a unified diff. Returns verdicts + stats. |
| GET | `/healthz` | Liveness probe. Always 200 if the process is up. |
| GET | `/readyz` | Readiness probe. Probes the LLM, returns 200/503. |
| GET | `/version` | Atalaia, detector, LLM-model versions. |

`/metrics` is on its own listener (`observability.metrics_addr`), not the main port.

## Auth

If `server.auth_token` (or `ATALAIA_SERVER_AUTH_TOKEN`) is set, `/check` requires `Authorization: Bearer <token>`. Probes and `/version` stay open so orchestrator health-checks work without secrets.

```http
POST /check HTTP/1.1
Host: atalaia.example.com
Authorization: Bearer s3cret
Content-Type: text/x-diff

<unified diff>
```

Missing or wrong token returns 401 with `WWW-Authenticate: Bearer realm="atalaia"`.

## POST /check

### Request

Two body formats. Use whichever your client speaks comfortably.

**`text/x-diff`** (recommended for raw piping):

```http
POST /check HTTP/1.1
Content-Type: text/x-diff

diff --git a/api/client.py b/api/client.py
@@ -1,3 +1,4 @@
 import requests
+TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
 ...
```

**`application/json`** (handy when the caller already has a JSON payload):

```http
POST /check HTTP/1.1
Content-Type: application/json

{"diff": "diff --git a/api/client.py b/api/client.py\n@@ -1,3 +1,4 @@\n import requests\n+TOKEN = \"ghp_...\"\n"}
```

Also accepted: `text/plain`, `application/x-patch`, missing/blank Content-Type (treated as raw diff).

**Body size cap**: `server.max_body_bytes` (default 10 MiB). Larger bodies return 400.

**Diff format**: standard unified diff with `diff --git` / `--- a/path` / `+++ b/path` / `@@` headers. Atalaia walks added lines (`+`) and treats unprefixed blank lines inside a hunk as context (real-world diffs from web APIs and editors that strip trailing whitespace).

### Response

200 with `application/json` on success. The shape is fixed:

```json
{
  "request_id": "01KRN34HMPNN6823H2676YF37A",
  "verdicts": [ ... ],
  "stats":    { ... }
}
```

#### `request_id`

Stable per call. Appears in atalaia's per-request log line, the audit log entry (when enabled), and the `X-Request-ID` response header. Use it to correlate a noisy alert back to the request that produced it.

If the caller sends an `X-Request-ID` header on the request, atalaia uses that value (validated: ≤ 128 chars, alphanumeric plus `-_.:`). Otherwise atalaia mints a fresh ULID. The chosen value always comes back on both the response header and the body field.

#### `verdicts[]`

One entry per dedup'd finding. Each verdict carries the detection trail (which scanners fired) **and** the LLM's decision.

```json
{
  "id": "78292567e712",
  "file": "api/client.py",
  "line": 2,
  "match_preview": "ghp_****q7r8",
  "verdict": "confirmed",
  "confidence": 0.95,
  "reason": "Bearer token used in API request headers.",
  "detections": [
    {
      "detector_type": "gitleaks",
      "detector_name": "github-pat",
      "rule": "github-pat",
      "verified": false
    }
  ]
}
```

Field by field:

- `id` (string) — `sha256(file + ":" + line + ":" + raw_match)[:12]`. Stable across re-runs. Use it to dedup alerts over time.
- `file`, `line` (string, int) — post-image location in the new file.
- `match_preview` (string) — redacted view of the matched value. URL credentials become `scheme://****:****@host/path`; opaque tokens become `<head4>****<tail4>`. Short matches collapse to `****`. **The raw match is never in the API response**, only in the opt-in audit log with `reveal_matches: true`.
- `verdict` (string) — `"confirmed"` or `"dismissed"`.
- `confidence` (float, 0-1) — model's stated confidence in the verdict. Sentinel and verified short-circuits use `1.0`. Gap-filled fallbacks (model didn't decide) use `0.0`.
- `reason` (string, ≤ 280 chars) — one-sentence rationale from the model, or a fixed string for short-circuits and gap-fills. Any verbatim occurrence of the raw match is scrubbed to its redacted preview before the reason leaves the process, so the raw secret never rides out in the explanation.
- `detections[]` — every scanner that fired on this `(file, line, match)`. A finding caught by gitleaks **and** trufflehog with `verified: true` shows both entries; that pair is the strongest pre-LLM signal and short-circuits to `confirmed: 1.0`. Detection fields:
  - `detector_type` — `gitleaks`, `trufflehog`, or `kingfisher`.
  - `detector_name` — the detector's own name for what fired (e.g. `aws`, `postgres`, `github-pat`).
  - `rule` — the rule ID. Often the same as `detector_name` for gitleaks; trufflehog usually echoes its detector name.
  - `verified` (bool) — true only when trufflehog confirmed the credential against the provider API (requires `detectors.trufflehog.verify: true`, off by default).

#### `stats`

Per-request observability. Counts, not summaries.

```json
{
  "detectors_run": ["gitleaks", "trufflehog"],
  "raw_findings": 5,
  "after_dedup": 3,
  "confirmed": 1,
  "dismissed": 2,
  "llm_invoked": true,
  "llm_calls": 1,
  "llm_model": "google/gemma-4-E4B-it",
  "llm_latency_ms": 4321,
  "total_latency_ms": 4892,
  "truncated": false
}
```

- `raw_findings` is pre-dedup, `after_dedup` is what the LLM saw. The difference is multiple scanners catching the same `(file, line, match)`.
- `llm_invoked: false` happens when every finding short-circuited (all verified, all sentinels) or zero findings. The response is sub-200ms in that case.
- `llm_calls > 1` means per-finding mode kicked in for a large diff (see `llm.context_budget`).
- `truncated: true` means the request had more findings than `llm.max_findings_per_request` and the response only contains the first N verdicts.
- `detector_errors[]` is present only when a detector failed to complete (timeout, crash, kill). Each entry is `{"detector": "trufflehog", "error": "signal: killed"}`. Its presence on a `200` means a **partial** scan: the verdicts are real, but at least one detector did not run, so a zero-finding result is *not* an authoritative "clean". Absent the field, all detectors completed. When *every* detector fails and nothing is found, `/check` returns `503` instead of a `200` (see status codes) so the caller can't mistake an un-run scan for a clean diff.

```json
"detector_errors": [
  {"detector": "trufflehog", "error": "signal: killed (stderr: )"}
]
```

### A realistic worked example

POST a small diff with three credentials of mixed verdict quality:

```diff
diff --git a/api/client.py b/api/client.py
@@ -1,3 +1,8 @@
 import requests
+# placeholder example, replaced at deploy time
+TEST_TOKEN = "AKIAIOSFODNN7EXAMPLE"
+# real prod creds
+API_TOKEN = "ghp_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8"
+s3 = boto3.client("s3", aws_access_key_id="AKIA5JNQXQABCDEFGHIJ", aws_secret_access_key="...")
```

Response:

```json
{
  "request_id": "01KRN34HMPNN6823H2676YF37A",
  "verdicts": [
    {
      "id": "a1b2c3d4e5f6",
      "file": "api/client.py",
      "line": 3,
      "match_preview": "AKIA****MPLE",
      "verdict": "dismissed",
      "confidence": 1.0,
      "reason": "AWS documentation sample access key",
      "detections": [
        {
          "detector_type": "gitleaks",
          "detector_name": "aws-access-token",
          "rule": "aws-access-token",
          "verified": false
        }
      ]
    },
    {
      "id": "b2c3d4e5f6a1",
      "file": "api/client.py",
      "line": 5,
      "match_preview": "ghp_****q7r8",
      "verdict": "confirmed",
      "confidence": 0.95,
      "reason": "Bearer token used directly in API client construction.",
      "detections": [
        {
          "detector_type": "gitleaks",
          "detector_name": "github-pat",
          "rule": "github-pat",
          "verified": false
        }
      ]
    },
    {
      "id": "c3d4e5f6a1b2",
      "file": "api/client.py",
      "line": 6,
      "match_preview": "AKIA****HIJ",
      "verdict": "confirmed",
      "confidence": 0.9,
      "reason": "Matched AWS access key ID in boto3 client initialization wired to a production-named bucket.",
      "detections": [
        {
          "detector_type": "gitleaks",
          "detector_name": "aws-access-token",
          "rule": "aws-access-token",
          "verified": false
        },
        {
          "detector_type": "trufflehog",
          "detector_name": "aws",
          "rule": "aws",
          "verified": false
        }
      ]
    }
  ],
  "stats": {
    "detectors_run": ["gitleaks", "trufflehog"],
    "raw_findings": 4,
    "after_dedup": 3,
    "confirmed": 2,
    "dismissed": 1,
    "llm_invoked": true,
    "llm_calls": 1,
    "llm_model": "google/gemma-4-E4B-it",
    "llm_latency_ms": 7421,
    "total_latency_ms": 7438,
    "truncated": false
  }
}
```

What each verdict tells the caller:

- **Verdict 1**: detector said "AWS access token", LLM (well, the sentinel short-circuit) recognised `AKIAIOSFODNN7EXAMPLE` as the canonical AWS docs sample and dismissed at full confidence.
- **Verdict 2**: detector said "github-pat", LLM saw it land in a Bearer header on a real client and confirmed.
- **Verdict 3**: two detectors fired on the same line; that's why `raw_findings: 4` collapsed to `after_dedup: 3`. The merged `detections` list keeps both, so callers can see the corroboration.

The caller's typical loop, in Python:

```python
for v in resp["verdicts"]:
    if v["verdict"] != "confirmed":
        continue
    detectors = ", ".join(f"{d['detector_type']}/{d['rule']}" for d in v["detections"])
    print(f"{v['file']}:{v['line']}  {v['match_preview']}  ({detectors})  conf={v['confidence']}  {v['reason']}")
    notify_developer(v)  # or open an issue, fail the build, etc
```

In Go, via `apitypes`:

```go
import "github.com/juanfont/atalaia/apitypes"

var resp apitypes.CheckResponse
if err := json.NewDecoder(httpResp.Body).Decode(&resp); err != nil {
    return err
}
for _, v := range resp.Verdicts {
    if v.Verdict != apitypes.VerdictConfirmed {
        continue
    }
    notifyDeveloper(v)
}
```

### Status codes

| Code | When |
|---|---|
| 200 | Adjudication succeeded. Body is `CheckResponse`. A partial scan (some detector failed but findings were still produced) is still a 200; check `stats.detector_errors`. |
| 400 | Invalid body, missing diff, body over `server.max_body_bytes`, unsupported Content-Type. |
| 401 | `server.auth_token` set, request missing or wrong. |
| 502 | LLM call failed (upstream timeout, parse error, transport error). Response body has an `{"error": "..."}` shape with the underlying message. |
| 503 | Not adjudicated, **retry with backoff**. Either the LLM queue is full (`llm.queue_max` reached), or the scan was inconclusive — every detector failed and nothing was found, so atalaia fails closed rather than return a false "clean". |

Errors all return `application/json` `{"error": "..."}`.

A `503` means the diff was **not** scanned. Treat it as retryable, never
as clean: retry with backoff, and alert if it persists. This is the
mirror of the partial-scan case above — a `200` with `detector_errors`
gives you real verdicts plus a coverage caveat; a `503` gives you
nothing and must be retried.

### False-positive prevention

The whole point of Atalaia is that the LLM removes noise the regex
detectors would otherwise dump on a developer. That removal is already
in the response: there's no separate endpoint or field to enable. A
**dismissed** verdict is a prevented false positive. The consumer can
surface this directly.

What you have to work with:

- `stats.dismissed` is the count of prevented false positives for this
  request. `stats.confirmed` is what actually needs a human.
- Each dismissed verdict in `verdicts[]` carries the full story: which
  detector fired (`detections[].detector_type` / `rule`), what the
  scanner thought it found, and why the LLM dismissed it (`reason`,
  `confidence`).

So "we prevented N false positives, here's what they were" is a filter
over the response you already have.

**Go**, using the [`apitypes`](../apitypes) package:

```go
import "github.com/juanfont/atalaia/apitypes"

type Prevented struct {
    File     string
    Line     int
    Detector string // e.g. "gitleaks/aws-access-token"
    Reason   string // the LLM's rationale
}

func preventedFalsePositives(resp apitypes.CheckResponse) []Prevented {
    var out []Prevented
    for _, v := range resp.Verdicts {
        if v.Verdict != apitypes.VerdictDismissed {
            continue
        }
        det := ""
        if len(v.Detections) > 0 {
            det = v.Detections[0].DetectorType + "/" + v.Detections[0].Rule
        }
        out = append(out, Prevented{
            File: v.File, Line: v.Line, Detector: det, Reason: v.Reason,
        })
    }
    return out
}

// In the watcher:
prevented := preventedFalsePositives(resp)
if len(prevented) > 0 {
    log.Printf("atalaia prevented %d false positive(s) on commit %s", len(prevented), sha)
    for _, p := range prevented {
        log.Printf("  %s:%d  %s  (%s)", p.File, p.Line, p.Detector, p.Reason)
    }
}
```

`resp.Stats.Dismissed` equals `len(prevented)`; use whichever reads
better at the call site.

**Python**:

```python
prevented = [v for v in resp["verdicts"] if v["verdict"] == "dismissed"]
if prevented:
    print(f"atalaia prevented {len(prevented)} false positive(s)")
    for v in prevented:
        det = v["detections"][0]
        print(f"  {v['file']}:{v['line']}  "
              f"{det['detector_type']}/{det['rule']}  "
              f"({v['reason']})")
```

#### Surfacing it to developers

How loud to be is a policy decision that lives in the consumer, not
Atalaia. Common shapes:

- **Silent win, counted.** Don't notify per-dismissal; just track
  `stats.dismissed` over time. The `atalaia_verdicts_total{verdict="dismissed"}`
  Prometheus counter already supports a "noise removed" dashboard with
  no consumer code at all.
- **Footnote on the confirmed alert.** When you notify a developer
  about a confirmed finding, append "Atalaia also dismissed N
  likely-false-positive matches in this diff" so they trust the filter.
- **Audit trail only.** Write dismissals to your own store keyed on the
  stable `id` (`sha256(file:line:match)[:12]`) so you can later answer
  "did we ever see this string and decide it was fine?" without
  re-running.

A dismissed verdict is not a guarantee. The LLM can be wrong, and the
`reason` / `confidence` fields are there so the consumer can choose how
much to trust a given dismissal. A common rule: surface dismissals with
`confidence < 0.7` for spot-checking, swallow the rest.

## GET /healthz

Liveness. Returns 200 as long as the process is up. **Never** returns 503. Use this for restart loops.

```json
{"status": "ok", "llm_reachable": true}
```

The `llm_reachable: true` is a backwards-compat field, not the real readiness signal; see `/readyz`.

## GET /readyz

Readiness. Returns 200/503 based on a cached LLM-reachability state that a background goroutine refreshes every `llm.healthcheck_interval` (default 30 s). The cache means a busy load balancer can't turn /readyz into an LLM DoS amplifier; the staleness check inside the watcher means a wedged poller fails closed to "not ready" instead of serving stale "ready" answers (threshold is 3× the interval). Use this for load-balancer health and orchestrator readiness gates. A `/readyz=503` should take the pod out of rotation but **not** restart it.

200:
```json
{"status": "ready", "llm_reachable": true}
```

503:
```json
{"status": "not_ready", "llm_reachable": false}
```

## GET /version

```json
{
  "atalaia": "0.1.0",
  "llm_model": "google/gemma-4-E4B-it",
  "prompt": "gemma4:8116c54e48f5",
  "gitleaks": "unknown",
  "trufflehog": "unknown",
  "kingfisher": "unknown"
}
```

`prompt` is the loaded prompt's `profile:hash` fingerprint. It changes whenever the on-disk template (`prompts/<profile>_{system,user}.tmpl`) changes, so you can confirm the live prompt matches the release — a deploy that updates the binary but not the `prompts/` directory shows a stale hash here while silently running the old prompt.

Detector versions are currently reported as `unknown`; follow-up item.

## Integration patterns

`docs/deployment.md` covers the three common shapes (pre-commit hook, CI gate, source-host webhook watcher) with worked GitLab examples. The API contract above is the same regardless of which caller you use.
