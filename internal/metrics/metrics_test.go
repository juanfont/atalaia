package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestMetricsRegisteredAndLabeled(t *testing.T) {
	CheckRequestsTotal.WithLabelValues("200").Inc()
	if got := testutil.ToFloat64(CheckRequestsTotal.WithLabelValues("200")); got != 1 {
		t.Errorf("CheckRequestsTotal{status=200}=%v, want 1", got)
	}

	DetectorFindingsTotal.WithLabelValues("gitleaks").Add(3)
	if got := testutil.ToFloat64(DetectorFindingsTotal.WithLabelValues("gitleaks")); got != 3 {
		t.Errorf("DetectorFindingsTotal{detector=gitleaks}=%v, want 3", got)
	}

	VerdictsTotal.WithLabelValues("confirmed").Inc()
	VerdictsTotal.WithLabelValues("dismissed").Add(2)
	if got := testutil.ToFloat64(VerdictsTotal.WithLabelValues("confirmed")); got != 1 {
		t.Errorf("VerdictsTotal{confirmed}=%v, want 1", got)
	}
	if got := testutil.ToFloat64(VerdictsTotal.WithLabelValues("dismissed")); got != 2 {
		t.Errorf("VerdictsTotal{dismissed}=%v, want 2", got)
	}

	LLMInflight.Inc()
	if got := testutil.ToFloat64(LLMInflight); got != 1 {
		t.Errorf("LLMInflight=%v, want 1", got)
	}
	LLMInflight.Dec()

	LLMMissingVerdictTotal.Inc()
	if got := testutil.ToFloat64(LLMMissingVerdictTotal); got != 1 {
		t.Errorf("LLMMissingVerdictTotal=%v, want 1", got)
	}
}

func TestCheckDurationHistogramAccepts(t *testing.T) {
	CheckDurationSeconds.WithLabelValues("detect").Observe(0.012)
	CheckDurationSeconds.WithLabelValues("llm").Observe(1.234)
	CheckDurationSeconds.WithLabelValues("total").Observe(1.250)
	// Smoke only — histograms aren't trivially inspectable without a registry,
	// the goal is to confirm no panic on the documented stage labels.
}
