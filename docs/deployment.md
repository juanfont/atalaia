# Deploying Atalaia

How to stand Atalaia up, put it on a network, and wire it into a source host. Worked example: GitLab. GitHub Enterprise, Bitbucket, Gitea look almost identical.

For the HTTP contract (request shapes, response anatomy, error codes), see [api.md](api.md). This doc covers everything around it.

## Pieces

Three moving parts:

1. **An LLM serving an OpenAI-compatible API.** Default: [vLLM](https://docs.vllm.ai) on a 10 GB-VRAM GPU. Anything that speaks `/v1/chat/completions` works (Ollama, llama.cpp's `llama-server`, mistral.rs, TGI, SGLang).
2. **Atalaia itself.** One Go binary, sibling process to the LLM. Holds nothing on disk between requests.
3. **A caller.** Event-driven watcher (webhook → fetch diff → POST), pre-commit hook, or CI gate.

Same host (loopback), private VLAN, or tailnet. Pick one.

## Where to run Atalaia

### 1. systemd unit

The reference shape. One binary, system user, hardened service unit.

```ini
# /etc/systemd/system/atalaia.service
[Unit]
Description=Atalaia secret-scanning service
After=network.target
Wants=vllm.service

[Service]
Type=exec
User=atalaia
Group=atalaia
EnvironmentFile=-/etc/atalaia/atalaia.env   # ATALAIA_SERVER_AUTH_TOKEN etc.
ExecStart=/usr/local/bin/atalaia serve --config /etc/atalaia/atalaia.yaml
Restart=on-failure
RestartSec=5

NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=/etc/atalaia
ReadWritePaths=/var/lib/atalaia

[Install]
WantedBy=multi-user.target
```

Secrets (`ATALAIA_SERVER_AUTH_TOKEN`, `ATALAIA_TAILSCALE_AUTH_KEY`) go in `/etc/atalaia/atalaia.env` (mode `0600`), pulled in via `EnvironmentFile=`. Keep them out of the YAML.

vLLM is a sibling `vllm.service`.

### 2. Container

`docker pull ghcr.io/juanfont/atalaia:latest`. Bundles pinned `trufflehog` and `kingfisher`, runs as uid 65532, prompts at `/etc/atalaia/prompts/`.

LLM on the host:

```sh
docker run --rm --name atalaia -p 8080:8080 \
  -e ATALAIA_LLM_ENDPOINT=http://host.docker.internal:8000/v1 \
  -e ATALAIA_LLM_MODEL=google/gemma-4-E4B-it \
  -e ATALAIA_SERVER_AUTH_TOKEN="$ATALAIA_TOKEN" \
  ghcr.io/juanfont/atalaia:latest
```

Custom detector configs bind-mounted:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/atalaia.yaml:/etc/atalaia/atalaia.yaml:ro" \
  -v "$PWD/gitleaks.toml:/etc/atalaia/gitleaks.toml:ro" \
  -e ATALAIA_SERVER_AUTH_TOKEN="$ATALAIA_TOKEN" \
  ghcr.io/juanfont/atalaia:latest
```

## Network posture

### Reverse proxy + TLS (recommended default)

Bind Atalaia to `127.0.0.1:8080`, terminate TLS at caddy/nginx/envoy on `:443`. The reverse proxy handles certs, rate limits, and IP-level access controls. Bearer token (`server.auth_token`) is defence in depth.

```caddy
atalaia.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Tailscale-only

`tailscale.enabled: true`, `tailscale.listen_only: true` joins Atalaia to a Tailscale or Headscale tailnet. Host port stays unbound. Only tailnet nodes allowed by ACL reach `/check`. The tailnet is already encrypted, no TLS terminator needed.

Tag the Atalaia node (`tag:atalaia`) and the caller (`tag:webhook-watcher`). Grant `tag:webhook-watcher → tag:atalaia:8080`.

### Probes

- `/healthz`, liveness. Always 200 if the process is up. Use this for restart loops.
- `/readyz`, readiness. Probes the LLM, returns 200/503. Use this for load-balancer health and orchestrator readiness gates.
- `/metrics`, Prometheus surface on a separate listener (`observability.metrics_addr`).

### Auth

`ATALAIA_SERVER_AUTH_TOKEN` (or `server.auth_token`) turns on bearer-token auth on `/check`. Probes and `/version` stay open so orchestrators don't need the secret.

```http
POST /check HTTP/1.1
Authorization: Bearer <token>
Content-Type: text/x-diff

<unified diff>
```

## Calling Atalaia

### Pre-commit hook

Block the commit when Atalaia returns at least one `confirmed` verdict.

```sh
#!/usr/bin/env bash
# .git/hooks/pre-commit  (or a managed-hook framework like lefthook)
set -e

DIFF=$(git diff --staged)
[ -z "$DIFF" ] && exit 0

RESP=$(printf '%s' "$DIFF" | curl -fsS \
    -H "Authorization: Bearer $ATALAIA_TOKEN" \
    -H 'Content-Type: text/x-diff' \
    --data-binary @- \
    "$ATALAIA_URL/check")

CONFIRMED=$(printf '%s' "$RESP" | jq -r '.stats.confirmed')
if [ "$CONFIRMED" -gt 0 ]; then
    printf '%s' "$RESP" | jq -r '.verdicts[] | select(.verdict=="confirmed") | "\(.file):\(.line)  \(.match_preview)  \(.reason)"'
    echo "atalaia: $CONFIRMED confirmed secret(s) in staged diff. Commit blocked."
    exit 1
fi
```

### CI gate

Same shape on the CI side. Diff merge-base..HEAD, POST, fail on any `confirmed`.

```yaml
# GitLab CI snippet
secret-scan:
  image: alpine:3
  before_script:
    - apk add --no-cache git curl jq
  script:
    - git fetch origin "$CI_MERGE_REQUEST_TARGET_BRANCH_NAME"
    - DIFF=$(git diff "origin/$CI_MERGE_REQUEST_TARGET_BRANCH_NAME...HEAD")
    - |
        RESP=$(printf '%s' "$DIFF" | curl -fsS \
            -H "Authorization: Bearer $ATALAIA_TOKEN" \
            -H 'Content-Type: text/x-diff' \
            --data-binary @- "$ATALAIA_URL/check")
        echo "$RESP" | jq .
        test "$(echo "$RESP" | jq -r '.stats.confirmed')" = "0"
```

Both snippets use `curl -f`, so a `503` (Atalaia busy or a scan it couldn't complete) exits non-zero and **fails closed** — the commit/pipeline is blocked, not waved through. That's deliberate: an un-adjudicated diff must not pass as clean. If you'd rather retry transient 503s before blocking, wrap the `curl` in a short retry loop; just don't downgrade the failure to success.

## GitLab webhook integration (worked example)

A small watcher service subscribes to GitLab push events, fetches each commit's diff, hands it to Atalaia, acts on `confirmed` verdicts.

### Architecture

```
GitLab ── push hook ──►  watcher (your service)
                            │
                            ├─ fetch commit diff via GitLab API
                            ├─ POST /check                       ─► Atalaia
                            │   diff bytes                          (filters with LLM)
                            ├─ for each "confirmed" verdict:
                            │    open issue / email author /
                            │    Slack ping / block merge
                            └─ ack to GitLab (under the 10s timeout)
```

Atalaia is stateless. The *watcher* is where you put policy:

- which projects to scan
- who to notify
- whether to block the MR
- how to deduplicate alerts over time

### Configuring GitLab

In **Admin Area → System Hooks** (or per-project **Settings → Webhooks**) add a hook:

- **URL**: `https://watcher.example.com/gitlab/push`
- **Trigger**: Push events
- **Secret token**: a long random string (verify in the handler)
- **SSL verification**: enabled

GitLab sends `application/json` push payloads and expects a 200 within ~10 seconds. Anything slower trips the retry queue. The watcher must **ACK immediately and adjudicate asynchronously**. Atalaia + the LLM can easily exceed 10s.

### Watcher (compact Go sketch)

```go
package main

import (
    "bytes"
    "context"
    "crypto/hmac"
    "crypto/sha256"
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "os"
    "strings"
    "time"

    gitlab "github.com/xanzy/go-gitlab"
)

type pushEvent struct {
    ProjectID int `json:"project_id"`
    Commits   []struct {
        ID string `json:"id"`
    } `json:"commits"`
}

type verdict struct {
    ID           string  `json:"id"`
    File         string  `json:"file"`
    Line         int     `json:"line"`
    MatchPreview string  `json:"match_preview"`
    Verdict      string  `json:"verdict"`
    Confidence   float64 `json:"confidence"`
    Reason       string  `json:"reason"`
}

type detectorError struct {
    Detector string `json:"detector"`
    Error    string `json:"error"`
}

type stats struct {
    DetectorErrors []detectorError `json:"detector_errors,omitempty"`
    Truncated      bool            `json:"truncated"`
}

type checkResponse struct {
    RequestID string    `json:"request_id"`
    Verdicts  []verdict `json:"verdicts"`
    Stats     stats     `json:"stats"`
}

// errRetryable marks a transient Atalaia response (503): queue full, or
// a scan that could not complete. The commit was NOT adjudicated, so it
// must be retried — never treated as clean.
var errRetryable = fmt.Errorf("atalaia: retryable")

// checkSem bounds how many commits the watcher adjudicates at once. A
// push (or a backfill of many pushes) can carry dozens of commits;
// without this the watcher fan-bombs Atalaia with concurrent /check
// calls. Size it to Atalaia's capacity, not GitLab's.
var checkSem = make(chan struct{}, 8)

func main() {
    glab, err := gitlab.NewClient(os.Getenv("GITLAB_TOKEN"),
        gitlab.WithBaseURL(os.Getenv("GITLAB_URL")))
    if err != nil {
        panic(err)
    }

    http.HandleFunc("/gitlab/push", handlePush(glab,
        os.Getenv("GITLAB_HOOK_TOKEN"),
        os.Getenv("ATALAIA_URL"),
        os.Getenv("ATALAIA_TOKEN")))

    http.ListenAndServe(":9000", nil)
}

func handlePush(glab *gitlab.Client, hookToken, atalaiaURL, atalaiaToken string) http.HandlerFunc {
    return func(w http.ResponseWriter, r *http.Request) {
        // 1. Verify the shared secret. GitLab sends it in X-Gitlab-Token.
        if !hmac.Equal([]byte(r.Header.Get("X-Gitlab-Token")), []byte(hookToken)) {
            http.Error(w, "forbidden", http.StatusForbidden)
            return
        }

        var ev pushEvent
        if err := json.NewDecoder(r.Body).Decode(&ev); err != nil {
            http.Error(w, err.Error(), http.StatusBadRequest)
            return
        }
        // 2. ACK immediately. GitLab times push hooks out around 10s.
        w.WriteHeader(http.StatusAccepted)

        // 3. Adjudicate asynchronously.
        go func() {
            for _, c := range ev.Commits {
                if err := process(glab, atalaiaURL, atalaiaToken, ev.ProjectID, c.ID); err != nil {
                    fmt.Fprintf(os.Stderr, "process %s: %v\n", c.ID, err)
                }
            }
        }()
    }
}

func process(glab *gitlab.Client, atalaiaURL, token string, projectID int, sha string) error {
    diffs, _, err := glab.Commits.GetCommitDiff(projectID, sha, nil)
    if err != nil {
        return err
    }
    unified := buildUnifiedDiff(diffs)
    if unified == "" {
        return nil
    }

    // Bound concurrent adjudications so a multi-commit push can't
    // flood Atalaia. Block until a slot is free.
    checkSem <- struct{}{}
    defer func() { <-checkSem }()

    // Retry transient 503s with backoff. A 503 means "not adjudicated"
    // (queue full or scan inconclusive); dropping it would silently
    // skip a possibly-dirty commit.
    var resp *checkResponse
    backoff := time.Second
    for attempt := 0; attempt < 4; attempt++ {
        ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
        resp, err = check(ctx, atalaiaURL, token, unified)
        cancel()
        if err == nil {
            break
        }
        if err == errRetryable {
            time.Sleep(backoff)
            backoff *= 2
            continue
        }
        return err
    }
    if err != nil {
        // Still failing after retries: alert rather than drop. An
        // un-adjudicated commit is an operational incident, not a clean.
        return fmt.Errorf("commit %s left un-adjudicated: %w", sha, err)
    }

    // A partial scan (one detector failed, another produced findings)
    // returns 200 with verdicts plus detector_errors. Act on the
    // verdicts, but flag the gap so coverage isn't silently incomplete.
    if len(resp.Stats.DetectorErrors) > 0 {
        fmt.Fprintf(os.Stderr, "commit %s: partial scan, detectors failed: %+v\n",
            sha, resp.Stats.DetectorErrors)
    }
    for _, v := range resp.Verdicts {
        if v.Verdict == "confirmed" {
            notify(projectID, sha, v) // email / slack / open issue / block merge
        }
    }
    return nil
}

func buildUnifiedDiff(files []*gitlab.Diff) string {
    var b strings.Builder
    for _, f := range files {
        oldPath, newPath := f.OldPath, f.NewPath
        if f.NewFile {
            oldPath = "/dev/null"
        }
        if f.DeletedFile {
            newPath = "/dev/null"
        }
        fmt.Fprintf(&b, "diff --git a/%s b/%s\n", f.OldPath, f.NewPath)
        fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", oldPath, newPath)
        b.WriteString(f.Diff)
        if !strings.HasSuffix(f.Diff, "\n") {
            b.WriteByte('\n')
        }
    }
    return b.String()
}

func check(ctx context.Context, endpoint, token, diff string) (*checkResponse, error) {
    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        endpoint+"/check", bytes.NewReader([]byte(diff)))
    if err != nil {
        return nil, err
    }
    req.Header.Set("content-type", "text/x-diff")
    if token != "" {
        req.Header.Set("authorization", "Bearer "+token)
    }

    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    switch resp.StatusCode {
    case http.StatusOK:
        var out checkResponse
        if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
            return nil, err
        }
        return &out, nil
    case http.StatusServiceUnavailable:
        // Queue full or scan inconclusive. Transient: retry, do not
        // treat as clean.
        return nil, errRetryable
    default:
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("atalaia: %d %s", resp.StatusCode, b)
    }
}

func notify(projectID int, sha string, v verdict) {
    // your policy: email the author, open an issue, post to Slack/Teams,
    // mark the MR un-mergeable via the API, etc.
    _ = sha256.New() // placeholder
}
```

### Things to get right

- **ACK fast, adjudicate slow.** GitLab's 10s window is a hard ceiling. LLM round-trip goes in the goroutine, never in the request handler.
- **Verify the hook token.** It's the only thing between your watcher and a public unauthenticated POST endpoint. Header: `X-Gitlab-Token`.
- **Deduplicate alerts.** Watcher receives every commit. Alert per-commit and you spam on rebases. Key dedup on `(project_id, finding_id)`. Atalaia's `finding_id` is stable across re-runs (`sha256(file:line:match)[:12]`).
- **Pick the right LLM context.** For typical commits (< 32K tokens) defaults are fine. For monorepo merges touching hundreds of files, see `llm.max_findings_per_request` and `llm.context_budget.input_tokens`. Response carries `stats.truncated: true` when the cap kicks in.
- **Treat 503 as "retry", never "clean".** Atalaia returns `503` when it can't adjudicate: the LLM queue is full, or a scan was inconclusive (a detector crashed/timed out and produced nothing). The commit was *not* scanned. Retry with backoff; if it still fails, raise an incident — do not let an un-adjudicated commit pass as clean. A `200` with a non-empty `stats.detector_errors[]` is a *partial* scan: the verdicts are real, but coverage was incomplete, so flag it.
- **Cap your own concurrency.** A push can carry dozens of commits and a backfill many pushes. Bound how many `/check` calls are in flight at once (the `checkSem` in the sketch). Atalaia bounds subprocess detectors and the LLM internally, but an unbounded watcher fan-out still buries it under queue depth and earns you 503s. Size the cap to Atalaia's capacity.
- **Policy lives in the watcher, not in Atalaia.** Atalaia returns verdicts. Whether to block the MR, open an issue, page someone is your call and will change over time. Keep policy out of the secret-scanner so you can re-tune without redeploying it.

### Operational checklist

- [ ] Atalaia + LLM healthchecked from your monitoring. Scrape `/metrics`, alert on `atalaia_check_requests_total{status="5xx"}` non-zero, on `atalaia_detector_errors_total` ticking up (scans failing/timing out), on `atalaia_llm_queue_depth` saturating, on `atalaia_llm_missing_verdict_total` ticking up.
- [ ] Watcher retries Atalaia 503s with backoff and alerts on un-adjudicated commits, rather than treating them as clean. Watcher bounds its own concurrent `/check` calls.
- [ ] `ATALAIA_SERVER_AUTH_TOKEN` rotated whenever the watcher's credential is rotated.
- [ ] Audit log opted in *only* on a separate, restricted volume. Raw matches land there when `observability.audit.reveal_matches: true`.
- [ ] Detector binaries (trufflehog, kingfisher) pinned via the container image or Makefile. Bump deliberately, not on every release.
