# Atalaia

<p align="center"><img src="atalaia_logo.png" alt="Atalaia logo" width="160"/></p>

<p align="center">
  <a href="https://github.com/juanfont/atalaia/actions/workflows/ci.yml"><img src="https://github.com/juanfont/atalaia/actions/workflows/ci.yml/badge.svg" alt="ci"></a>
  <a href="https://github.com/juanfont/atalaia/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-Apache%202.0-blue.svg" alt="license"></a>
</p>

Secret detection for git commits, with a local LLM cutting the false positives.

Atalaia is a stateless HTTP service: clients POST a unified diff, Atalaia runs `gitleaks` and `trufflehog` against it, hands the resulting findings to a local OpenAI-compatible LLM (default: [vLLM](https://docs.vllm.ai) serving Gemma 4 E4B), and returns one verdict per finding — `confirmed` or `dismissed`. The detectors keep the recall of regex scanning; the LLM lifts the precision close enough that confirmed findings can drive direct developer notifications without a human triage step.

Everything runs on your own infrastructure. No outbound calls in the default posture.

> _atalaia_, from Andalusi Arabic _ṭalāyiʿ_ through Galician-Portuguese, the watchtower posted ahead of the army to see what is coming.

## Why

Open-source secret scanners are precision-bound: a typical repo run produces enough false positives that real findings get lost. Verifying every hit against a provider API (as trufflehog does) helps for some credential types but doesn't catch the rest. A small language model reading each finding in context can sort the two piles cheaply.

Atalaia is the regex-then-LLM pattern packaged as a self-hostable service with a local LLM. The LLM does not detect; it decides.

## Architecture

```
                ┌───────────────────────────────────────────────┐
                │ atalaia (single Go binary)                    │
                │                                               │
  POST /check   │   parse diff                                  │
  ───────────►  │      │                                        │
  diff bytes    │      ▼                                        │
                │   run detectors in parallel                   │
                │      ├─ gitleaks (library, in-process)        │
                │      ├─ trufflehog (subprocess, AGPL fence)   │
                │      └─ kingfisher (subprocess, optional)     │
                │      │                                        │
                │      ▼                                        │
                │   canonical findings, deduplicated            │
                │      │                                        │
                │      ▼                                        │
                │   short-circuits (verified secrets,           │
                │   known sentinels)                            │
                │      │                                        │
                │      ▼                                        │
                │   LLM call ────────────────────►  vLLM        │
                │   schema-constrained, one call    (sibling    │
                │   covering all findings           process)    │
                │      │                                        │
                │      ▼                                        │
                │   verdicts + detection trail + stats          │
                └───────────────────────────────────────────────┘
```

Atalaia is one Go binary. The LLM is a sibling process (vLLM, llama.cpp, Ollama, anything OpenAI-compatible). They share a host or talk across a private network.

## Quickstart

Build the binary:

```sh
make build         # produces ./atalaia
make install-detectors   # pins and installs trufflehog and kingfisher
```

Start an OpenAI-compatible model server. For vLLM on a 10 GB-VRAM GPU:

```sh
vllm serve google/gemma-4-E4B-it \
    --quantization fp8 --kv-cache-dtype fp8 \
    --max-model-len 131072 --max-num-seqs 1 \
    --host 127.0.0.1 --port 8000
```

Copy the example config and adjust:

```sh
cp config.example.yaml /etc/atalaia/atalaia.yaml
```

Verify the config parses and required binaries are reachable:

```sh
./atalaia validate -c /etc/atalaia/atalaia.yaml
./atalaia probe    -c /etc/atalaia/atalaia.yaml   # lands in milestone 4
./atalaia serve    -c /etc/atalaia/atalaia.yaml
```

`POST /check` accepts either `text/x-diff` (raw unified diff) or `application/json` with `{"diff": "..."}` and returns a list of verdicts plus per-request stats. `GET /healthz` is the liveness probe (always 200 if the process is up); `GET /readyz` is readiness (200/503 based on LLM reachability). `GET /version` reports atalaia, detector, and LLM-model versions.

## Container

Each tagged release publishes a multi-arch image to GHCR with `atalaia` plus pinned versions of `trufflehog` and `kingfisher` baked in (~110 MB, runs as a non-root user):

```sh
docker pull ghcr.io/juanfont/atalaia:latest
```

Defaults work out of the box for both subprocess detectors (built-in rulesets) — point at an LLM endpoint and go:

```sh
docker run --rm -p 8080:8080 \
  -e ATALAIA_LLM_ENDPOINT=http://vllm:8000/v1 \
  -e ATALAIA_LLM_MODEL=google/gemma-4-E2B-it \
  ghcr.io/juanfont/atalaia:latest
```

For custom rulesets, bind-mount the config files into `/etc/atalaia/` and point `atalaia.yaml` at the in-container paths:

```sh
docker run --rm -p 8080:8080 \
  -v $PWD/atalaia.yaml:/etc/atalaia/atalaia.yaml:ro \
  -v $PWD/gitleaks.toml:/etc/atalaia/gitleaks.toml:ro \
  -e ATALAIA_LLM_ENDPOINT=http://vllm:8000/v1 \
  ghcr.io/juanfont/atalaia:latest
```

The prompts live at `/etc/atalaia/prompts/` inside the image and the binary defaults already reference that path. Trufflehog is AGPL-3.0 — see [LICENSE](LICENSE) and the upstream source at [trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog).

## Configuration

Every key in `atalaia.yaml` is overridable via env vars with the `ATALAIA_` prefix and dots replaced by underscores — `llm.endpoint` becomes `ATALAIA_LLM_ENDPOINT`. Search path: `./atalaia.yaml`, `$HOME/.atalaia/atalaia.yaml`, `/etc/atalaia/atalaia.yaml`. CLI `-c` overrides both.

See [config.example.yaml](config.example.yaml) for the full schema. Highlights:

- **Detectors**: pick which to run (`detectors.enabled`), supply custom rule files (`detectors.gitleaks.config`, `detectors.trufflehog.config`, `detectors.kingfisher.rules`), include/exclude trufflehog detectors, and pass arbitrary additional CLI flags via per-detector `extra_args`.
- **LLM**: any OpenAI-compatible chat-completions endpoint; tune the queue (`max_inflight`, `queue_max`), context budgets, and the prompt profile.
- **Tailscale**: opt-in `tsnet` listener so Atalaia is reachable only from your tailnet — ACLs replace IP allowlists. `auth_key` must come from `ATALAIA_TAILSCALE_AUTH_KEY`, never from the YAML.

## Network posture

Atalaia is plain HTTP. There are two recommended deployment shapes:

**1. Loopback Atalaia behind a TLS-terminating reverse proxy.** Bind Atalaia to `127.0.0.1:8080`, run caddy/nginx/envoy on `:443` with a cert, forward `/check` to the local port. Auth and rate-limiting live at the proxy; bearer tokens via `ATALAIA_SERVER_AUTH_TOKEN` are a defence-in-depth layer.

Minimal Caddyfile:

```
atalaia.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

**2. Tailscale-only via the built-in `tsnet` listener.** Set `tailscale.enabled: true` and `tailscale.listen_only: true` in the config; supply the auth key via `ATALAIA_TAILSCALE_AUTH_KEY`. The host port stays unbound and only tailnet peers allowed by ACL can reach `/check`. No TLS termination needed — the tailnet is already encrypted.

For either posture, optionally gate `/check` with a bearer token (`server.auth_token`). `/healthz`, `/readyz`, and `/version` stay open so orchestrator probes work without secrets. `/metrics` is on its own listener (`observability.metrics_addr`) so the main port can be locked down without losing scrape access.

## Integration

Atalaia is source-agnostic — anything that can produce a unified diff can call `/check`. Common patterns:

1. **Source-host webhooks** (GitLab system hooks, GitHub push events): a small watcher subscribes, fetches the commit diff, POSTs it.
2. **Pre-commit hooks**: pipe `git diff --staged` to `curl` before the commit lands.
3. **CI gates**: compare the merge target against the source branch and POST the diff as a required-status check.

Atalaia returns verdicts; the caller decides whether to block, notify, or log. It never stores diffs, findings, or verdicts.

## Roadmap

| Milestone | Scope                                                                                                  | Status |
| --------- | ------------------------------------------------------------------------------------------------------ | ------ |
| 1         | Foundation: config schema, CLI tree (`serve`/`validate`/`probe`/`version`), HTTP shell with `/metrics` | done   |
| 2         | Detector layer: gitleaks (library), trufflehog (subprocess), kingfisher (subprocess), dedup, redaction | done   |
| 3         | API surface: `POST /check`, `GET /healthz`, `GET /version` returning findings (pre-LLM)                | done   |
| 4         | LLM filter: OpenAI client, semaphore, schema-constrained verdicts, sentinel/verified short-circuits    | done   |
| 5         | Context tiering & batching for large diffs                                                             | done   |
| 6         | Full Prometheus metrics + opt-in audit log                                                             | done   |
| 7         | Optional Tailscale (`tsnet`) listener                                                                  | done   |

## Security and threat model

- **In-memory only.** Atalaia never persists the diff, findings, or verdicts. Logs carry redacted previews, never raw matches.
- **No outbound calls in the default config.** Trufflehog runs with `--no-verification`. The only egress is Atalaia → the configured LLM endpoint.
- **License fence.** Trufflehog is AGPL-3.0; Atalaia invokes it as a subprocess and never imports it as a Go module. Atalaia ships under Apache 2.0.
- **The LLM endpoint must be trusted.** Prompts contain raw matches — the model needs to see the value to judge it. Run vLLM on the same network as Atalaia, or point at a third-party provider only when policy allows.

## License

Apache 2.0. See [LICENSE](LICENSE).

---
