package llm

import (
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
)

func TestShortCircuit_VerifiedConfirms(t *testing.T) {
	d := detector.DedupedFinding{
		ID: "id1", File: "a.py", Line: 5, Match: "anything",
		AnyVerified: true,
	}
	v, ok := shortCircuit(d)
	if !ok || v.Verdict != VerdictConfirmed || v.Confidence != 1.0 {
		t.Errorf("verified short-circuit failed: ok=%v v=%+v", ok, v)
	}
}

func TestShortCircuit_SentinelDismisses(t *testing.T) {
	d := detector.DedupedFinding{
		ID: "id1", File: "a.py", Line: 5,
		Match: "AKIAIOSFODNN7EXAMPLE",
	}
	v, ok := shortCircuit(d)
	if !ok || v.Verdict != VerdictDismissed || v.Confidence != 1.0 {
		t.Errorf("sentinel short-circuit failed: ok=%v v=%+v", ok, v)
	}
}

func TestShortCircuit_SentinelPrefix(t *testing.T) {
	d := detector.DedupedFinding{
		ID: "id1", Match: "sk-test-abc123def456",
	}
	v, ok := shortCircuit(d)
	if !ok || v.Verdict != VerdictDismissed {
		t.Errorf("prefix sentinel failed: ok=%v v=%+v", ok, v)
	}
}

func TestShortCircuit_AmbiguousFallsThrough(t *testing.T) {
	d := detector.DedupedFinding{
		ID: "id1", Match: "AKIA1ABCDEFGHIJKLMNO",
	}
	if _, ok := shortCircuit(d); ok {
		t.Errorf("expected fall-through for ambiguous match")
	}
}
