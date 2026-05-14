# Changelog

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning: [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- GitHub Actions CI workflow (unit + integration jobs).
- goreleaser config and tag-triggered release workflow producing
  linux/darwin × amd64/arm64 tarballs with the `atalaia.Version`
  ldflag wired.
- Optional bearer-token auth on `/check`. Set `server.auth_token`
  (or `ATALAIA_SERVER_AUTH_TOKEN`). Requests need
  `Authorization: Bearer <token>`. `/healthz`, `/readyz`, `/version`
  stay open.
- `/readyz` readiness probe. Probes the LLM, returns 200/503.
  `/healthz` is now liveness, always 200 if the process is up.
- `server.idle_timeout` (default 120s) wired into `http.Server`.
- Per-request structured log line with request_id, sizes, verdict
  counts, and stage timings. No raw matches.
- README "Network posture" section covering loopback + reverse
  proxy and the tailscale-only alternatives.
- Multi-arch container image published to `ghcr.io/juanfont/atalaia`
  on each tag. Bundles pinned `trufflehog` and `kingfisher`,
  runs as a non-root user, prompts at `/etc/atalaia/prompts/`.
- New `docs/deployment.md` covering systemd, container, reverse
  proxy, tailscale shapes, probe and auth wiring, and a worked
  GitLab webhook integration (compact Go watcher sketch +
  operational checklist).

### Changed

- **Breaking** for orchestrator probes: `/healthz` no longer reports
  LLM reachability and never returns 503. Point readiness probes at
  `/readyz` instead.
- `trufflehog` invocations include `--no-update` to keep the binary
  from auto-rewriting itself in containers and non-root installs.
- README "Roadmap" table removed. v1 has shipped, CHANGELOG is the
  canonical record from here.
- README logo bumped from 160px to 240px wide.

## [0.1.0], v1

First end-to-end release. The regex-then-LLM secret filter described
in the design doc, in seven milestones.

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

### Security

- No outbound calls in the default configuration. Trufflehog runs
  with `--no-verification`. The only network egress is to the
  configured LLM endpoint.
- License fence: trufflehog (AGPL-3.0) is always a subprocess.
  Atalaia ships under Apache 2.0.
- No raw matches in API responses or non-audit logs.
