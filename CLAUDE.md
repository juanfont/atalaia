# CLAUDE.md

Guidance for Claude Code (claude.ai/code) working in this repository.

## Project

Atalaia is a stateless HTTP service that filters false positives out of
`gitleaks` and `trufflehog` secret-scanner findings using a local
OpenAI-API-compatible LLM (default: vLLM serving Gemma 4 E4B). Callers
POST a unified diff to `/check`. Atalaia runs the regex detectors,
deduplicates findings, asks the LLM to adjudicate, returns verdicts.
Detectors detect, the LLM decides.

When the design doc disagrees with the code, the design wins.

## Commands

Module: `github.com/juanfont/atalaia`. Binary entry: `cmd/atalaia`.

- Build: `make build` (or `go build ./cmd/atalaia`)
- Run: `./atalaia serve -c /etc/atalaia/atalaia.yaml`
- Subcommands: `serve`, `validate`, `probe`, `version`
- Tests: `go test ./...`. Single package: `go test ./internal/types`.
  Single test: `go test ./internal/types -run TestName`
- Lint/format: `go vet ./...`, `gofmt -l .`
- Tidy deps: `go mod tidy`
- Version is injected via `-ldflags "-X github.com/juanfont/atalaia.Version=<v>"`
  (defaults to `dev`).

CI runs gofmt, go vet, go test, plus an integration job that installs
the pinned `trufflehog` from the Makefile and exercises the subprocess
adapter. Tagged pushes (`v*.*.*`) trigger goreleaser, which produces
linux/darwin × amd64/arm64 tarballs plus a multi-arch container image
at `ghcr.io/juanfont/atalaia`.

## Architecture

One Go binary, sibling to a vLLM (or any OpenAI-compatible) process on
loopback or a private network.

### Request lifecycle for `POST /check`

1. Parse the body. Either `text/x-diff` raw, or JSON `{"diff": "..."}`.
2. Run all enabled detectors in parallel against the diff.
3. Normalize each detector's output into a canonical
   `Finding{DetectorType, DetectorName, Rule, File, Line, Match, Verified}`
   and deduplicate by `(file, line, match)`.
4. Short-circuit before the LLM:
   - trufflehog `verified: true` ⇒ auto-confirm, `confidence: 1.0`.
   - Known sentinel values (`AKIAIOSFODNN7EXAMPLE`,
     `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`, `sk-test-…`,
     `ya29.dummy`, …) ⇒ auto-dismiss, `confidence: 1.0`.
5. Acquire one slot of the LLM semaphore (`llm.max_inflight`, default 1)
   and call the model.
6. Return `{request_id, verdicts[], stats{}}`. The raw match is **never**
   returned, only `match_preview` (redacted). Finding/verdict `id` is
   `sha256(file + ":" + line + ":" + raw_match)[:12]`, stable across
   re-runs.

`/healthz` is liveness (always 200 if the process is up). `/readyz` is
readiness (probes the LLM, returns 200/503). `/version` reports atalaia +
LLM model + detector versions.

### Detector layer

Small Go interface:

```go
type Detector interface {
    Name() string
    Scan(ctx context.Context, diff []byte) ([]Finding, error)
}
```

- **gitleaks**: in-process Go library (`github.com/zricethezav/gitleaks/v8/detect`),
  MIT.
- **trufflehog**: **subprocess only** (`trufflehog stdin --json
  --no-verification --no-update`). It is AGPL-3.0. The process boundary
  is the license fence. **Never import trufflehog as a Go module.**
  That would relicense Atalaia to AGPL. Apache 2.0 is deliberate.
- **kingfisher**: subprocess, optional, disabled by default.

Detector binaries are pinned in the Makefile and bundled into the
container image. Enabling/disabling is a config flag, not a reinstall.

### LLM layer

- Backend: any OpenAI chat-completions-compatible endpoint. Default
  deployment: vLLM with Gemma 4 E4B (FP8 weights + FP8 KV cache,
  `--max-num-seqs 1`, `--max-model-len 131072`, prefix caching).
- Response shape via `response_format: json_schema` when the backend
  supports it. Atalaia currently omits `response_format` because vLLM's
  xgrammar wedged Gemma 4 E2B (see [internal-docs/vllm-host.md](internal-docs/vllm-host.md)).
  The parser accepts both `{"verdicts": [...]}` envelope and bare
  top-level arrays.
- Prompts live in `prompts/<profile>_{system,user}.tmpl`. Schema is the
  contract, prompt is the implementation. Retune per model family
  without changing the API.
- Context strategy is tiered: if the diff plus findings fit
  `llm.context_budget.input_tokens`, send one call with the full diff
  (richer cross-file context). Otherwise switch to per-finding mode
  with `finding_context_lines` (default 30) lines around each match,
  packed into one or more sequential calls under a single semaphore
  slot.
- Failure modes after guided decoding: missing `finding_id`, empty
  reason, refusals. Fill gaps with a conservative fallback verdict
  (`confirmed`, `confidence: 0.0`, reason
  `"model returned no verdict for this finding"`) and bump
  `atalaia_llm_missing_verdict_total`. Don't fail the whole request.
- Hard cap `max_findings_per_request` (default 200). Beyond this,
  truncate and set `stats.truncated: true`.

Verdict correlation is by `finding_id`, never by array position.
Required for tolerating out-of-order model output.

### Concurrency

Detectors run in parallel within a request. Only the **LLM stage** is
gated by the semaphore. Requests with zero findings never enter the
queue. `queue_max` (default 16) returns `503` past that.

### Statelessness

Atalaia never persists diffs, findings, matches, or verdicts.
Everything is in-memory for the lifetime of one request. Audit logging
is opt-in (`observability.audit.enabled`) and writes redacted previews
unless `observability.audit.reveal_matches: true`.

## Code layout

- [cmd/atalaia/](cmd/atalaia/), `main` (zerolog setup, honors
  `NO_COLOR`) and the Cobra command tree under
  [cli/](cmd/atalaia/cli/). Subcommands self-register in `init()`.
- [app.go](app.go) (`package atalaia`), top-level lifecycle:
  `NewAtalaiaApp` → `Serve` → `Shutdown` / `Close` (10s default timeout).
  Owns the main `http.Server`, the optional host listener (when tsnet
  is enabled with `listen_only: false`), the metrics `http.Server`, the
  tsnet server, and the audit writer. Builds the `mux.Router`, builds
  detectors via `detector.BuildEnabled`, builds the `llm.Adjudicator`,
  hands them to `internal/api.NewApp`. `/metrics` runs on its own
  listener (`observability.metrics_addr`).
- [internal/types](internal/types/), canonical `Config` + Viper loader
  + validator. Borrowed from headscale (`ReadViperConfig` comment says
  "Stolen from Headscale :)"). Validates that
  `tailscale.auth_key` never appears literally in the loaded YAML
  (`ValidateAuthKeyNotInFile`).
- [internal/api](internal/api/), HTTP handlers (`/check`, `/healthz`,
  `/readyz`, `/version`). Bearer-token middleware on `/check` only.
  Per-request structured log line at the end of `Check` covers
  request_id, sizes, verdict counts, stage timings. No raw matches.
- [internal/detector](internal/detector/), `Detector` interface +
  gitleaks/trufflehog/kingfisher adapters + unified-diff walker +
  dedup + `FindingID` helper + `BuildEnabled` factory.
- [internal/llm](internal/llm/), chat-completions client, `Adjudicator`
  (single-call vs per-finding mode), semaphore (with metrics
  side-effects), short-circuits, prompt loader, response parser.
- [internal/redact](internal/redact/), `Preview` masking (URL-aware,
  head/tail-keep fallback).
- [internal/audit](internal/audit/), JSONL append writer (mutex
  serialized) + `Nop()` fallback when disabled.
- [internal/metrics](internal/metrics/), Prometheus counters,
  histograms, gauges. Bumped from handlers and from the LLM semaphore.
- [prompts/](prompts/), Go `text/template` templates per profile.
  Default profile is `gemma4`.
- [docs/](docs/), operator-facing docs ([docs/deployment.md](docs/deployment.md)
  is the GitLab integration story).
- [internal-docs/](internal-docs/), gitignored ops notes about the
  specific deployment hosts and the install gotchas we hit.

## Configuration

Loaded via Viper, wired through Cobra.

- Search paths (in order): `./atalaia.yaml`,
  `$HOME/.atalaia/atalaia.yaml`, `/etc/atalaia/atalaia.yaml`. Override
  with `-c <path>`.
- Env override prefix is `ATALAIA_`, dots → underscores
  (`ATALAIA_LLM_ENDPOINT`). Durations parse natively (`30s`, `2m`, `1h`).
- Secrets (`server.auth_token`, `tailscale.auth_key`) must come from
  the environment, not the YAML. Ship them via `EnvironmentFile=` in
  the systemd unit.

## Conventions and constraints worth remembering

- **License fence**: trufflehog (AGPL-3.0) is always a subprocess.
  Atalaia ships under Apache 2.0. The boundary is non-negotiable.
- **No outbound calls in default config**: trufflehog runs with
  `--no-verification`. The only network egress is Atalaia to its
  configured LLM endpoint. Don't add features that quietly reach
  external APIs.
- **No raw matches in API responses or non-audit logs**, ever. The
  default `/check` response and application logs carry `match_preview`
  only. Raw matches go to the audit log only when the operator
  explicitly opts in.
- **Detectors detect, the LLM decides.** Don't push detection
  responsibility to the model. Recall comes from regex, precision
  comes from the filter.
- **Statelessness is a design goal**, not an accident. Don't introduce
  on-disk state for findings, verdicts, or diffs.
- **Verdict correlation is by `finding_id`**, never by array position.
  Required for tolerating out-of-order model output.
- **Logging**: zerolog. JSON in production (`log.format: json` swaps
  the global logger), console writer locally. `NO_COLOR` honored.
- **Writing style**: direct, economical. Short sentences. No
  hedging, no preamble, no filler. Dashes (em/en) get cut, replaced by
  periods, commas, or restructured sentences.
