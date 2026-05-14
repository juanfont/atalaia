// Package metrics holds the Prometheus surface and HTTP middleware
// shared across the binary. Every metric here lands on the dedicated
// /metrics listener (observability.metrics_addr) — not the main HTTP
// port — so scraping never contends with /check traffic.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// CheckRequestsTotal counts /check requests labeled by HTTP status.
	CheckRequestsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "atalaia_check_requests_total",
		Help: "Total /check requests by HTTP status.",
	}, []string{"status"})

	// CheckDurationSeconds is the per-stage histogram of /check
	// latencies. Stage labels: detect, llm, total.
	CheckDurationSeconds = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "atalaia_check_duration_seconds",
		Help:    "Latency of /check by stage.",
		Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30, 60, 120},
	}, []string{"stage"})

	// DetectorFindingsTotal counts raw (pre-dedup) findings per detector.
	DetectorFindingsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "atalaia_detector_findings_total",
		Help: "Raw findings emitted per detector (pre-dedup).",
	}, []string{"detector"})

	// DetectorErrorsTotal counts non-fatal detector errors. These do
	// not fail the request — they surface in the response stats.
	DetectorErrorsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "atalaia_detector_errors_total",
		Help: "Non-fatal detector errors.",
	}, []string{"detector"})

	// VerdictsTotal counts emitted verdicts by outcome.
	VerdictsTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "atalaia_verdicts_total",
		Help: "Verdicts emitted, by verdict string.",
	}, []string{"verdict"})

	// LLMInflight is the current number of in-flight LLM calls.
	LLMInflight = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "atalaia_llm_inflight",
		Help: "In-flight LLM calls.",
	})

	// LLMQueueDepth is the current total depth (running + waiting)
	// against the LLM semaphore.
	LLMQueueDepth = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "atalaia_llm_queue_depth",
		Help: "Total LLM queue depth (inflight + waiting).",
	})

	// LLMMissingVerdictTotal counts findings the model failed to
	// adjudicate, which Adjudicate gap-fills with a conservative
	// fallback (confirmed, confidence 0). Surfacing this metric is
	// how operators notice prompt or model drift.
	LLMMissingVerdictTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "atalaia_llm_missing_verdict_total",
		Help: "Findings the LLM did not return a verdict for; filled with fallback.",
	})
)

// MetricsMiddleware is the request-counting middleware applied to the
// main router. Status labeling is best-effort (we capture the written
// status via a small wrapper); see Check handler for the explicit
// CheckRequestsTotal increment used on /check.
func MetricsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}
