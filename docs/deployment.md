# Deploying Atalaia

This guide covers the practical end-to-end story: how to stand up Atalaia + the LLM, how to put it on a network, and how to wire it into common source hosts. The worked example for integrations is GitLab; GitHub Enterprise / Bitbucket / Gitea look almost identical.

The README has the elevator pitch and config reference. This document is the operational manual.

## Pieces

A typical deployment has three moving parts:

1. **An LLM serving an OpenAI-compatible API.** Default is [vLLM](https://docs.vllm.ai) on a single 10 GB-VRAM GPU host. Anything that speaks `/v1/chat/completions` works (Ollama, llama.cpp's `llama-server`, mistral.rs, TGI, SGLang).
2. **Atalaia itself.** One Go binary, sibling process to the LLM. Holds nothing on disk between requests.
3. **A caller.** Either an event-driven watcher (webhook → fetch diff → POST), a pre-commit hook, or a CI gate.

Atalaia and the LLM can run on the same host (loopback), on a private VLAN, or on a tailnet.

## Where to run Atalaia

### 1. systemd unit

The reference shape. One Go binary, a system user, hardened service unit.

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

Secrets (`ATALAIA_SERVER_AUTH_TOKEN`, `ATALAIA_TAILSCALE_AUTH_KEY`) live in `/etc/atalaia/atalaia.env` (mode `0600`) and are pulled in via `EnvironmentFile=`. Keep them out of the YAML.

vLLM is a sibling `vllm.service` per the layout in [internal-docs](../internal-docs/) (or your own deployment notes).

### 2. Container

`docker pull ghcr.io/juanfont/atalaia:latest`. The image bundles pinned `trufflehog` and `kingfisher`, runs as non-root (uid 65532), and the prompts live at `/etc/atalaia/prompts/` so the binary defaults already point at them.

Minimal run with the LLM on the host:

```sh
docker run --rm --name atalaia -p 8080:8080 \
  -e ATALAIA_LLM_ENDPOINT=http://host.docker.internal:8000/v1 \
  -e ATALAIA_LLM_MODEL=google/gemma-4-E2B-it \
  -e ATALAIA_SERVER_AUTH_TOKEN="$ATALAIA_TOKEN" \
  ghcr.io/juanfont/atalaia:latest
```

With custom detector configs bind-mounted in:

```sh
docker run --rm -p 8080:8080 \
  -v "$PWD/atalaia.yaml:/etc/atalaia/atalaia.yaml:ro" \
  -v "$PWD/gitleaks.toml:/etc/atalaia/gitleaks.toml:ro" \
  -e ATALAIA_SERVER_AUTH_TOKEN="$ATALAIA_TOKEN" \
  ghcr.io/juanfont/atalaia:latest
```

Compose example with a sibling vLLM container is in the upstream docs; pin the model and reserve the GPU there.

## Network posture

### Reverse proxy + TLS (recommended default)

Bind Atalaia to `127.0.0.1:8080`, terminate TLS at caddy/nginx/envoy on `:443`. The reverse proxy handles certs, rate limits, and IP-level access controls; the bearer token (`server.auth_token`) is defence in depth.

```caddy
atalaia.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

### Tailscale-only

The built-in `tsnet` listener (`tailscale.enabled: true`, `tailscale.listen_only: true`) joins Atalaia directly to a Tailscale or Headscale tailnet. The host port stays unbound; only tailnet nodes allowed by ACL can reach `/check`. The tailnet is already encrypted, so no TLS terminator is needed.

Tag the Atalaia node (`tag:atalaia`) and the calling watcher (`tag:webhook-watcher`); grant only `tag:webhook-watcher → tag:atalaia:8080` in your ACLs.

### Probes

- `/healthz` — liveness. Always 200 if the process is up. Use this for restart loops.
- `/readyz` — readiness. Probes the LLM and returns 200/503. Use this for load-balancer health and orchestrator readiness gates.
- `/metrics` — Prometheus surface on a separate listener (`observability.metrics_addr`).

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

The lightest integration. Block a commit when Atalaia returns at least one `confirmed` verdict on the staged diff.

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
    echo "atalaia: $CONFIRMED confirmed secret(s) in staged diff — commit blocked."
    exit 1
fi
```

### CI gate

Same idea on the CI side. Diff merge-base..HEAD, POST, fail the job on any `confirmed`.

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

## GitLab webhook integration (worked example)

The most useful shape: a small watcher service that subscribes to GitLab push events, fetches each commit's diff, hands it to Atalaia, and acts on `confirmed` verdicts.

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

Atalaia is stateless and source-agnostic by design. The *watcher* is where you put policy:

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

GitLab sends `application/json` push payloads and expects a 200 within ~10 seconds. Anything slower trips the retry queue, so the watcher must **ACK immediately and adjudicate asynchronously** — Atalaia + the LLM can easily exceed 10 s.

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

type checkResponse struct {
    RequestID string    `json:"request_id"`
    Verdicts  []verdict `json:"verdicts"`
}

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
        // 2. ACK immediately. GitLab times push hooks out around 10 s.
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

    ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
    defer cancel()

    verdicts, err := check(ctx, atalaiaURL, token, unified)
    if err != nil {
        return err
    }
    for _, v := range verdicts {
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

func check(ctx context.Context, endpoint, token, diff string) ([]verdict, error) {
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
    if resp.StatusCode != http.StatusOK {
        b, _ := io.ReadAll(resp.Body)
        return nil, fmt.Errorf("atalaia: %d %s", resp.StatusCode, b)
    }

    var out checkResponse
    if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
        return nil, err
    }
    return out.Verdicts, nil
}

func notify(projectID int, sha string, v verdict) {
    // your policy: email the author, open an issue, post to Slack/Teams,
    // mark the MR un-mergeable via the API, etc.
    _ = sha256.New() // placeholder
}
```

### Things to get right

- **ACK fast, adjudicate slow.** GitLab's 10 s window is a hard ceiling. Do the LLM round-trip in the goroutine, never in the request handler.
- **Verify the hook token.** It's the only thing standing between your watcher and a public unauthenticated POST endpoint. The header is `X-Gitlab-Token`.
- **Deduplicate alerts.** The watcher receives every commit. If you alert per-commit you'll spam on rebases. Key dedup on `(project_id, finding_id)` — Atalaia's `finding_id` is stable across re-runs (it's `sha256(file:line:match)[:12]`).
- **Pick the right LLM context.** For typical commits (small, < 32K tokens) the default config is fine. For monorepo merges that touch hundreds of files, see `llm.max_findings_per_request` and `llm.context_budget.input_tokens` — the response carries `stats.truncated: true` when the cap kicks in.
- **Policy lives in the watcher, not in Atalaia.** Atalaia returns verdicts; whether to block the MR / open an issue / page someone is your call, and changes over time. Keep that policy out of the secret-scanner so you can re-tune without redeploying it.

### Operational checklist

- [ ] Atalaia + LLM healthchecked from your monitoring (scrape `/metrics`, alert on `atalaia_check_requests_total{status="5xx"}` non-zero, on `atalaia_llm_queue_depth` saturating, on `atalaia_llm_missing_verdict_total` ticking up).
- [ ] `ATALAIA_SERVER_AUTH_TOKEN` rotated whenever the watcher's credential is rotated.
- [ ] Audit log opted in *only* on a separate, restricted volume. Raw matches land there when `observability.audit.reveal_matches: true`.
- [ ] Detector binaries (trufflehog/kingfisher) pinned via the container image or Makefile — bump deliberately, not on every release.
