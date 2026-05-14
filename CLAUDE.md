# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Atalaia is a stateless HTTP service that filters false positives out of `gitleaks` and `trufflehog` secret-scanner findings using a local OpenAI-API-compatible LLM (default: vLLM serving Gemma 4 E4B). Callers POST a unified diff to `/check`; Atalaia runs the regex detectors, deduplicates findings, asks the LLM to adjudicate, and returns verdicts. The detectors detect, the LLM only decides.

The authoritative source of truth for design, API shape, prompts, and constraints is the design document the user keeps locally; the code is currently a thin skeleton (empty README, no tests, stub handlers, a couple of compile-blocking mistakes — see "Current state" below). When design and code disagree, the design wins.

## Commands

Module: `github.com/juanfont/atalaia`. Binary entry: `cmd/atalaia`.

- Build: `go build ./cmd/atalaia`
- Run: `go run ./cmd/atalaia serve` (planned subcommands: `serve`, `validate`, `probe`, `version`; only `version` is wired today)
- Test: `go test ./...`; single package `go test ./internal/types`; single test `go test ./internal/types -run TestName`
- Lint/format: `go vet ./...`, `gofmt -l .`
- Tidy deps: `go mod tidy`
- Version is injected via `-ldflags "-X github.com/juanfont/atalaia/cmd/atalaia/cli.Version=<v>"` (defaults to `dev`).

## Current state (skeleton, not yet runnable end-to-end)

Treat as known-broken / to-be-finished, not as bugs to file:

- [app.go:62](app.go#L62) `Serve` is missing its `return` and doesn't actually start the HTTP server.
- [internal/api/app.go:6](internal/api/app.go#L6) imports `go/types` (stdlib AST package) instead of `github.com/juanfont/atalaia/internal/types` — this package will not compile until fixed.
- [internal/api/app.go](internal/api/app.go) `NewApp` registers `/check` but has no `return`; [internal/api/handlers.go](internal/api/handlers.go) `Check` is empty.
- [cmd/atalaia/cli/root.go:23](cmd/atalaia/cli/root.go#L23) the config-file flag help still says `/etc/mellon/config.yaml` and `initConfig` reads `MELLON_CONFIG` — leftover from the project this was cribbed from. The design specifies `ATALAIA_*` env and `/etc/atalaia/` paths; align as part of finishing the CLI.
- [internal/types/config.go](internal/types/config.go) validates `listen_addr` but never reads it into `Config`. The design's full schema (server, detectors, llm, observability, tailscale) is not modeled yet.
- No detector layer, no LLM client, no semaphore, no prompt templates — these all need to be created per the design.

## Architecture (target, per design doc)

Atalaia is one Go binary, sibling to a vLLM (or any OpenAI-compatible) process on loopback or a private network.

### Request lifecycle for `POST /check`

1. Parse the body — either `text/x-diff` raw, or JSON `{"diff": "..."}`.
2. Run all enabled detectors in parallel against the diff.
3. Normalize each detector's output into a canonical `Finding{DetectorType, DetectorName, Rule, File, Line, Match, Verified}` and deduplicate by `(file, line, match)`.
4. Short-circuit before the LLM:
   - trufflehog `verified: true` → auto-confirm, `confidence: 1.0`.
   - Known sentinel values (`AKIAIOSFODNN7EXAMPLE`, `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, etc.) → auto-dismiss, `confidence: 1.0`.
5. Acquire one slot of the LLM semaphore (`llm.max_inflight`, default 1) and call the model.
6. Return `{request_id, verdicts[], stats{}}`. The raw match is **never** returned — only `match_preview` (redacted). Finding/verdict `id` is `sha256(file + ":" + line + ":" + raw_match)[:12]`, stable across re-runs.

Also expose `GET /healthz` (probes the LLM with a one-token completion, 200/503) and `GET /version` (atalaia version + detector versions + LLM model).

### Detector layer

Small Go interface, three implementations in v1:

```go
type Detector interface {
    Name() string
    Scan(ctx context.Context, diff []byte) ([]Finding, error)
}
```

- **gitleaks**: imported as a Go library (`github.com/zricethezav/gitleaks/v8/detect`). MIT, no contagion.
- **trufflehog**: **subprocess only** (`trufflehog stdin --json --no-verification`). It is AGPL-3.0; the process boundary is the license fence. **Do not import trufflehog as a Go module under any circumstances** — that would relicense Atalaia to AGPL. The design picks Apache 2.0 deliberately.
- **kingfisher**: subprocess, optional, disabled by default.

Detector binaries are installed on the host and pinned by version in the release process. Enabling/disabling is a config flag, not a reinstall.

### LLM layer

- Backend: any OpenAI chat-completions-compatible endpoint. Default deployment: vLLM with Gemma 4 E4B (FP8 weights + FP8 KV cache, `--max-num-seqs 1`, `--max-model-len 131072`, prefix caching).
- Response shape is enforced server-side via `response_format: json_schema` (vLLM's guided decoding) — the schema is in the design doc; verdicts are correlated to inputs by `finding_id`, never by position.
- Prompts live in `prompts/<profile>.tmpl`. The **schema is the contract; the prompt is the implementation** — expect to retune per model family without changing the API.
- Context strategy is tiered: if the diff plus findings fit `llm.context_budget.input_tokens`, send one call with the full diff (richer cross-file context); otherwise switch to per-finding mode with `finding_context_lines` (default 30) lines around each match, packed into one or more sequential calls under a single semaphore slot.
- Failure modes after guided decoding: missing `finding_id`, empty reason, refusals. Fill gaps with a conservative fallback verdict (`confirmed`, `confidence: 0.0`, reason `"model returned no verdict for this finding"`) and bump a metric — don't fail the whole request.
- Hard cap `max_findings_per_request` (default 200): beyond this, truncate and set `stats.truncated: true`.

### Concurrency

Detectors run in parallel within a request. Only the **LLM stage** is gated by the semaphore — requests with zero findings never enter the queue. `queue_max` (default 16) returns `503` past that.

### Statelessness

Atalaia never persists diffs, findings, matches, or verdicts. Everything is in-memory for the lifetime of one request. Audit logging is opt-in and writes redacted previews unless the deployment explicitly opts into raw matches.

## Code layout

Target layout aligned with the design (some of this doesn't exist yet — create new files in these locations rather than reshuffling):

- [cmd/atalaia/](cmd/atalaia/) — `main` (zerolog setup, honors `NO_COLOR`) and the Cobra command tree under [cli/](cmd/atalaia/cli/). Subcommands self-register in `init()` (see [version.go](cmd/atalaia/cli/version.go)). New subcommands `serve`, `validate`, `probe` belong here.
- [app.go](app.go) (`package atalaia`) — top-level lifecycle: `NewAtalaiaApp` → `Serve` → `Shutdown` / `Close` (10s default timeout). Owns the `http.Server`, builds the `mux.Router`, attaches [internal/metrics.MetricsMiddleware](internal/metrics/metrics.go), exposes `/metrics` via `promhttp`, and delegates feature routes to `internal/api`.
- [internal/types](internal/types/) — canonical `Config` + Viper loader/validator. Borrowed from headscale (`ReadViperConfig` comment says "Stolen from Headscale :)"); expect to extend with the design's `server`, `detectors`, `llm`, `observability`, `tailscale` sections.
- [internal/api](internal/api/) — HTTP handlers (`/check`, `/healthz`, `/version`). Currently the only registered route is `/check` and the handler is empty.
- [internal/metrics](internal/metrics/) — Prometheus counters and request-counting middleware. The design names several more (`atalaia_check_duration_seconds`, `atalaia_detector_findings_total`, `atalaia_llm_inflight`, etc.); add here.

New packages to create when implementing the design: a `detector` package with the interface and three adapters, an `llm` package for the OpenAI client + prompt templating + semaphore, and a `redact` helper for `match_preview`.

## Configuration

Loaded via Viper, wired through Cobra.

- Search paths (in order): `./atalaia.yaml`, `$HOME/.atalaia/atalaia.yaml`, `/etc/atalaia/atalaia.yaml`. Override with `-c <path>`.
- Env override prefix is `ATALAIA_`, dots → underscores (e.g. `ATALAIA_LLM_ENDPOINT`). Durations parse natively (`30s`, `2m`, `1h`).
- Secrets (notably `tailscale.auth_key`) must never live in the YAML; ship them via `EnvironmentFile=` in the systemd unit so Viper picks them up from the env.

## Conventions and constraints worth remembering

- **License fence**: trufflehog (and anything else AGPL) is always a subprocess. The project ships under Apache 2.0 and that boundary is non-negotiable.
- **No outbound calls in default config**: trufflehog runs with `--no-verification`. The only network egress is Atalaia → its configured LLM endpoint. Don't add features that quietly reach external APIs.
- **No raw matches in responses or non-audit logs**, ever. Logs and the default `/check` response carry `match_preview` only. Raw matches go to the audit log only when the operator explicitly opts in.
- **Detectors detect, the LLM decides**. Don't push detection responsibility to the model — recall comes from regex, precision comes from the filter.
- **Statelessness is a design goal**, not an accident. Don't introduce on-disk state for findings/verdicts/diffs.
- **Verdict correlation is by `finding_id`**, never by array position — required for tolerating out-of-order model output.
- **Logging**: zerolog, JSON in production (`log.format: json` swaps the global logger), console writer locally; `NO_COLOR` is honored.
