# Atalaia Grafana dashboard

[`atalaia-dashboard.json`](atalaia-dashboard.json) is a ready-to-import
dashboard for the Prometheus metrics Atalaia exposes on its dedicated
`/metrics` listener (`observability.metrics_addr`, default
`0.0.0.0:9090`).

## Import

1. Point Prometheus at Atalaia's metrics endpoint:

   ```yaml
   scrape_configs:
     - job_name: atalaia
       static_configs:
         - targets: ["atalaia-host:9090"]
   ```

2. In Grafana: **Dashboards → New → Import → Upload JSON file**, pick
   `atalaia-dashboard.json`, and select your Prometheus data source.

The dashboard has `datasource`, `job`, and `instance` template variables,
so it works across multiple Atalaia instances without editing.

## Panels

The dashboard leads with what the LLM filter *does* — noise removed and
real secrets surfaced — and keeps operational health in one collapsed
row at the bottom.

| Section | Panels | What it tells you |
|---|---|---|
| What the filter did this window | false positives prevented, real secrets confirmed, noise filtered %, model answer rate | The value, at a glance, over the selected time range |
| Adjudication | confirmed vs dismissed, noise filtered over time, regex-surfaced vs LLM-kept, this-window-by-outcome | The decision stream and the false-positive load absorbed |
| What the scanners feed it | findings by detector, findings per request | The candidate stream the model has to weigh |
| Model reliability & speed | gap-fills, decision latency, throughput & concurrency | Whether the model is answering, and how fast |
| Operations (health) | /check by status, detector errors, queue + total p95, process memory/goroutines | Collapsed — incident debugging |

Key idea: **recall comes from the regex detectors, precision comes from
the LLM.** "Noise filtered" (dismissed share) is the filter's reason to
exist; "model answer rate" is `1 − gap-fills/verdicts`, the reliability
signal. The detect-vs-llm latency split lives in the Operations row.

## Signals worth alerting on

These map directly to incident classes Atalaia has actually hit:

```yaml
groups:
  - name: atalaia
    rules:
      # Detectors timing out / being SIGKILLed — the burst-saturation class.
      - alert: AtalaiaDetectorErrors
        expr: sum(rate(atalaia_detector_errors_total[5m])) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Atalaia detectors are erroring (timeout/kill)"

      # Inconclusive scans / queue-full — callers are being told to retry.
      - alert: AtalaiaHigh5xx
        expr: |
          sum(rate(atalaia_check_requests_total{status=~"5.."}[5m]))
            / clamp_min(sum(rate(atalaia_check_requests_total[5m])), 0.0001) > 0.05
        for: 10m
        labels: { severity: warning }
        annotations:
          summary: "Atalaia 5xx ratio above 5%"

      # Model failing to return verdicts — prompt/model drift.
      - alert: AtalaiaGapFills
        expr: sum(rate(atalaia_llm_missing_verdict_total[15m])) > 0.01
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Atalaia is gap-filling LLM verdicts (prompt/model drift?)"

      # LLM queue saturated — 503s imminent. Tune to your llm.queue_max.
      - alert: AtalaiaLLMQueueSaturated
        expr: max(atalaia_llm_queue_depth) >= 16
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Atalaia LLM queue at capacity"
```

A sudden jump in **confirm ratio** is also worth watching: it can mean
the prompt regressed (e.g. a deploy updated the binary but not the
`prompts/` directory). Cross-check `GET /version` — the `prompt` field is
the loaded prompt's `profile:hash` fingerprint and will reveal a stale
template.
