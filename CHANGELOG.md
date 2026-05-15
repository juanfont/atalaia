# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Opt-in tool-calling path via `llm.use_tools`. When true, Atalaia
  sends a `submit_verdicts` function tool with the VerdictSchema as
  the OpenAI tools API expects, forces `tool_choice` to that
  function, and parses `tool_calls[0].function.arguments` instead
  of message content. Eliminates gap-fills on any tool-supporting
  backend (Gemma 4 with `--tool-call-parser gemma4`, Qwen 2.5 with
  `--tool-call-parser hermes`, Mistral, etc.). New unit tests
  cover the tool path and the missing-tool-call error case.
- Inline JSON shape example in the user prompt template so backends
  without tool calling still produce the right shape consistently.
  Fixes a bug where non-Gemma models would emit JSON with invented
  finding_ids, triggering atalaia's gap-fill fallback.

### Changed

- **Breaking**: `llm.use_tools` now defaults to `true`. Tool calling
  is the right mechanism for structured output and what the design
  doc's reference vLLM deployment supports. Set `llm.use_tools: false`
  for backends without a registered tool-call parser (some smaller
  hosted providers, certain Ollama or llama.cpp builds, or vLLM
  serving a model family for which no `--tool-call-parser` is wired).
  vLLM with the wrong parser returns a clear 400 to `/check` which
  atalaia surfaces as a 502; flip to false if you see that.
- `INTEGRATION_MIN_AGREEMENT` default lowered to 0.6 to reflect
  honest per-run variance with tool calling on Qwen2.5-7B-AWQ
  (4-6 agreements out of 6 across runs, 0 gap-fills).


### Added

- Integration corpus under `internal/integration/testdata/diffs/`
  with six fixtures exercising the LLM filter end-to-end (real AWS
  key in boto3 init, GitHub PAT in Bearer header, Slack bot token in
  WebClient, AKIA-format key in tests fixture, AKIA-format key in
  docs example, high-entropy placeholder in `os.environ.get`
  default). Build-tagged (`integration`), gated on
  `ATALAIA_INTEGRATION_URL`. Aggregate agreement gate
  (`INTEGRATION_MIN_AGREEMENT`, default 0.5) accommodates small-
  model variance while still surfacing prompt regressions.
- `make smoke-corpus CONFIG=...` (`scripts/smoke-corpus.sh`)
  builds atalaia, stands it up on a non-default port, runs the
  corpus, tears down.


## [0.1.0], 2026-05-14

First public release. The regex-then-LLM secret filter described in
the design doc, plus CI, container, and the first round of operational
hardening (auth, readiness split, structured logs).

### Added

- **Config schema** (server, detectors, llm + context budget +
  profiles, observability + audit, tailscale, log) loaded via Viper
  with the `ATALAIA_` env prefix.
- **CLI tree**: `serve`, `validate`, `probe`, `version` (cobra
  subcommands) with `-c/--config` and per-subcommand RunE.
- **Detector layer** behind a `Detector` interface. Adapters for
  gitleaks (in-process library, MIT), trufflehog (subprocess, AGPL
  fence), kingfisher (subprocess, opt-in). Unified-diff walker
  tolerant of trailing-space-stripped context lines. Dedup by
  `(file, line, match)` with detection-trail preservation.
  Per-detector custom config files and `extra_args` escape hatches.
- **Redaction** (`internal/redact`). URL-aware mask that keeps hosts
  visible, head/tail-keep fallback for opaque tokens.
- **HTTP API**: `POST /check` (text/x-diff or JSON), `GET /healthz`,
  `GET /version`. ULID request IDs. Max-body cap, parallel-detector
  timeout.
- **LLM filter** (`internal/llm`):
  - OpenAI chat-completions client.
  - Semaphore with `queue_max` ⇒ HTTP 503 when full.
  - Short-circuits: verified ⇒ confirmed (1.0), known sentinels
    (`AKIAIOSFODNN7EXAMPLE`, `sk-test-…`, `ya29.dummy`, …) ⇒ dismissed
    (1.0).
  - Gap-fill for findings the model didn't decide (conservative
    `confirmed` at confidence 0, metric-bumped).
  - Response parser accepts both `{"verdicts": [...]}` envelope and
    bare top-level arrays.
- **Tiered context**: single-call when the diff fits the input
  budget. Per-finding mode otherwise, with ±N context windows packed
  into sequential batches under a single semaphore slot. Hard
  `max_findings_per_request` cap surfaced as `truncated: true` in
  stats.
- **Observability**:
  - Prometheus metrics on a dedicated listener
    (`observability.metrics_addr`): `atalaia_check_requests_total`,
    `_check_duration_seconds`, `_detector_findings_total`,
    `_detector_errors_total`, `_verdicts_total`, `_llm_inflight`,
    `_llm_queue_depth`, `_llm_missing_verdict_total`.
  - Opt-in JSONL audit sink (`observability.audit`). Raw matches
    only when `reveal_matches: true`. Preview-only by default.
- **Optional `tsnet` listener** (`tailscale.enabled`). Main router
  binds on a Tailscale or Headscale tailnet. `listen_only` toggles
  the additional host listener. Auth key must come from
  `ATALAIA_TAILSCALE_AUTH_KEY`. A YAML-level linter rejects it
  appearing literally in the config file.
- **Bearer-token auth on `/check`**. Set `server.auth_token` (or
  `ATALAIA_SERVER_AUTH_TOKEN`). Requests need
  `Authorization: Bearer <token>`. `/healthz`, `/readyz`, `/version`
  stay open.
- **`/readyz` readiness probe.** Probes the LLM, returns 200/503.
  `/healthz` is now liveness, always 200 if the process is up.
- `server.idle_timeout` (default 120s) wired into `http.Server`.
- Per-request structured log line with `request_id`, sizes, verdict
  counts, stage timings. No raw matches.
- GitHub Actions CI (unit + integration jobs).
- goreleaser config and tag-triggered release workflow producing
  linux/darwin × amd64/arm64 tarballs with the `atalaia.Version`
  ldflag wired.
- Multi-arch container image published to `ghcr.io/juanfont/atalaia`
  on each tag. Bundles pinned `trufflehog` and `kingfisher`, runs
  as a non-root user, prompts at `/etc/atalaia/prompts/`.
- `docs/deployment.md`: systemd, container, reverse proxy, tailscale
  shapes; probe and auth wiring; worked GitLab webhook integration
  (Go watcher sketch + operational checklist).
- `make test-integration` (mirrors the CI integration job) and
  `make smoke CONFIG=...` (end-to-end against a real LLM via
  `scripts/smoke.sh`).

### Security

- No outbound calls in the default configuration. Trufflehog runs
  with `--no-verification`. The only network egress is to the
  configured LLM endpoint.
- License fence: trufflehog (AGPL-3.0) is always a subprocess.
  Atalaia ships under Apache 2.0.
- No raw matches in API responses or non-audit logs.
