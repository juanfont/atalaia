# Atalaia API

The contract callers integrate against. Everything Atalaia exposes is
HTTP. There are four endpoints. The interesting one is `POST /check`.

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

A ULID. Stable per call; appears in atalaia's per-request log line and the audit log entry (when enabled), so you can correlate a noisy alert back to the request that produced it.

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
- `reason` (string, ≤ 280 chars) — one-sentence rationale from the model, or a fixed string for short-circuits and gap-fills.
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
  "llm_model": "google/gemma-4-E2B-it",
  "llm_latency_ms": 4321,
  "total_latency_ms": 4892,
  "truncated": false
}
```

- `raw_findings` is pre-dedup, `after_dedup` is what the LLM saw. The difference is multiple scanners catching the same `(file, line, match)`.
- `llm_invoked: false` happens when every finding short-circuited (all verified, all sentinels) or zero findings. The response is sub-200ms in that case.
- `llm_calls > 1` means per-finding mode kicked in for a large diff (see `llm.context_budget`).
- `truncated: true` means the request had more findings than `llm.max_findings_per_request` and the response only contains the first N verdicts.

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
    "llm_model": "google/gemma-4-E2B-it",
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

The caller's typical loop:

```python
for v in resp["verdicts"]:
    if v["verdict"] != "confirmed":
        continue
    detectors = ", ".join(f"{d['detector_type']}/{d['rule']}" for d in v["detections"])
    print(f"{v['file']}:{v['line']}  {v['match_preview']}  ({detectors})  conf={v['confidence']}  {v['reason']}")
    notify_developer(v)  # or open an issue, fail the build, etc
```

### Status codes

| Code | When |
|---|---|
| 200 | Adjudication succeeded. Body is `CheckResponse`. |
| 400 | Invalid body, missing diff, body over `server.max_body_bytes`, unsupported Content-Type. |
| 401 | `server.auth_token` set, request missing or wrong. |
| 502 | LLM call failed (upstream timeout, parse error, transport error). Response body has an `{"error": "..."}` shape with the underlying message. |
| 503 | LLM queue is full (`llm.queue_max` reached). Retry later with backoff. |

Errors all return `application/json` `{"error": "..."}`.

## GET /healthz

Liveness. Returns 200 as long as the process is up. **Never** returns 503. Use this for restart loops.

```json
{"status": "ok", "llm_reachable": true}
```

The `llm_reachable: true` is a backwards-compat field, not the real readiness signal; see `/readyz`.

## GET /readyz

Readiness. Probes the LLM with a one-token completion and returns 200/503 based on the result. Use this for load-balancer health and orchestrator readiness gates. A `/readyz=503` should take the pod out of rotation but **not** restart it.

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
  "llm_model": "google/gemma-4-E2B-it",
  "gitleaks": "unknown",
  "trufflehog": "unknown",
  "kingfisher": "unknown"
}
```

Detector versions are currently reported as `unknown`; follow-up item.

## Integration patterns

`docs/deployment.md` covers the three common shapes (pre-commit hook, CI gate, source-host webhook watcher) with worked GitLab examples. The API contract above is the same regardless of which caller you use.
