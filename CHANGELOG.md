# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Background LLM reachability watcher. A goroutine pings the LLM
  every `llm.healthcheck_interval` (default 30 s) and caches the
  result; `/readyz` reads the cached state instead of probing on
  every call. The cache caps probe traffic at a steady 2 req/min
  regardless of how often the orchestrator hits /readyz. If the
  goroutine dies or the host wedges (last probe older than 3×
  interval), the cache fails closed to "not ready" so traffic is
  shifted off the pod instead of serving stale 200s.

### Changed

- `INTEGRATION_MIN_AGREEMENT` default bumped to 0.8. The corpus
  hits 6/6 cleanly on Gemma 4 E4B with tools and FP8; a lower
  floor wasn't catching regressions any more.

## [0.2.1], 2026-05-17

### Added

- `POST /check` accepts a caller-supplied `X-Request-ID` header
  and uses it as the `request_id` (in the response body, the
  per-request log line, the audit entry, and the `X-Request-ID`
  response header). When the header is missing or fails validation
  (≤ 128 chars, alphanumeric plus `-_.:`), atalaia mints a ULID
  as before. Lets callers propagate their own trace IDs across
  the stack.

## [0.2.0], 2026-05-15

### Added

- `github.com/juanfont/atalaia/apitypes`: public Go package with
  the wire-shape types (`CheckResponse`, `Verdict`, `Detection`,
  `Stats`, `HealthzResponse`, `VersionResponse`, `ErrorResponse`,
  `CheckRequest`, `Verdict*` constants). External consumers can
  decode `/check` responses without redefining the schema. Stdlib
  only, no transitive pull-in of gitleaks, vLLM SDKs, viper, or
  any other server-side weight. Includes a JSON-roundtrip test
  that locks down the tag set.
- `docker-compose.yml` quickstart: bundles atalaia with a local
  Ollama serving `qwen2.5:1.5b`. `docker compose up -d` then POST
  diffs to `localhost:8080`. The first call triggers a one-time
  model pull. Slow on CPU but good enough to try the pipeline end
  to end without standing up a GPU.

### Changed

- `internal/api/types.go` removed. Call sites in `internal/api`
  now reference `apitypes.Verdict`, `apitypes.CheckResponse`, etc.
  directly. Flag-day rename, no compatibility aliases.
- `VerdictPendingLLM` constant dropped. Was a milestone-3
  placeholder that never appeared in a shipped response.
- README quickstart leads with the compose flow; the
  build-from-source path moves to a subsection.

## [0.1.0], 2026-05-15

First public release. The regex-then-LLM secret filter described in
the design doc, end to end: detectors, dedup, LLM adjudication with
tool calling, observability, container, CI.

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
  Trufflehog invocations include `--no-update` so the binary works
  in read-only containers.
- **Redaction** (`internal/redact`). URL-aware mask that keeps hosts
  visible, head/tail-keep fallback for opaque tokens.
- **HTTP API**: `POST /check` (text/x-diff or JSON), `GET /healthz`
  (liveness, always 200), `GET /readyz` (readiness, probes the LLM
  and returns 200/503), `GET /version`. ULID request IDs. Max-body
  cap, parallel-detector timeout, configurable idle timeout. Optional
  bearer-token auth on `/check` via `server.auth_token` (or
  `ATALAIA_SERVER_AUTH_TOKEN`); probes and `/version` stay open.
  Per-request structured log line with request_id, sizes, verdict
  counts, stage timings. No raw matches.
- **LLM filter** (`internal/llm`):
  - OpenAI chat-completions client.
  - Semaphore with `queue_max` ⇒ HTTP 503 when full.
  - Short-circuits: verified ⇒ confirmed (1.0), known sentinels
    (`AKIAIOSFODNN7EXAMPLE`, `sk-test-…`, `ya29.dummy`, …) ⇒ dismissed
    (1.0).
  - **Tool calling** (default on, `llm.use_tools: true`): sends a
    `submit_verdicts` function with the verdict schema, parses
    `tool_calls[0].function.arguments`. Eliminates structural
    failures on any tool-supporting backend (Gemma 4 with
    `--tool-call-parser gemma4`, Qwen 2.5 with
    `--tool-call-parser hermes`, Mistral, etc.).
  - Content-parsing fallback for backends without a tool-call
    parser (`llm.use_tools: false`). Accepts both
    `{"verdicts": [...]}` envelope and bare top-level arrays; the
    user prompt template carries an inline JSON shape example so
    non-Gemma backends still produce the right shape.
  - Gap-fill for findings the model didn't decide (conservative
    `confirmed` at confidence 0, metric-bumped).
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
- **Release plumbing**: GitHub Actions CI (unit + integration jobs);
  goreleaser config and tag-triggered release workflow producing
  linux/darwin × amd64/arm64 tarballs with the `atalaia.Version`
  ldflag wired; multi-arch container image published to
  `ghcr.io/juanfont/atalaia` per tag, bundling pinned `trufflehog`
  and `kingfisher`, runs as a non-root user, prompts at
  `/etc/atalaia/prompts/`.
- **Local make targets**: `make test-integration` mirrors the CI
  integration job. `make smoke CONFIG=…` runs a single-fixture
  end-to-end against a real LLM. `make smoke-corpus CONFIG=…` runs
  the full integration corpus (six fixtures under
  `internal/integration/testdata/diffs/`) and grades aggregate
  agreement (`INTEGRATION_MIN_AGREEMENT`, default 0.6).
- **Docs**: `docs/deployment.md` covers systemd, container, reverse
  proxy + TLS, and tailscale-only shapes, plus a worked GitLab
  webhook integration (Go watcher sketch + operational checklist).

### Security

- No outbound calls in the default configuration. Trufflehog runs
  with `--no-verification`. The only network egress is to the
  configured LLM endpoint.
- License fence: trufflehog (AGPL-3.0) is always a subprocess.
  Atalaia ships under Apache 2.0.
- No raw matches in API responses or non-audit logs.
