package llm

import (
	"strings"

	"github.com/juanfont/atalaia/internal/detector"
)

// Sentinels is the hard-coded set of documented sample values that
// every secret-scanner allowlists (or should). Any finding whose
// match equals one of these is auto-dismissed before the LLM is
// involved.
var Sentinels = map[string]string{
	"AKIAIOSFODNN7EXAMPLE":                     "AWS documentation sample access key",
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY": "AWS documentation sample secret access key",
	"AKIA1234567890ABCDEF":                     "AWS placeholder access key",
}

// SentinelPrefixes match anything starting with these strings.
// Vendor-specific test-token families fall here.
var SentinelPrefixes = []string{
	"sk-test-",   // OpenAI / Stripe-style test prefix
	"pk_test_",   // Stripe publishable test key
	"sk_test_",   // Stripe secret test key
	"ya29.dummy", // Google OAuth dummy token
}

// classifySentinel returns ("", false) if the match is not a known
// sentinel, or (reason, true) if it is.
func classifySentinel(match string) (string, bool) {
	if reason, ok := Sentinels[match]; ok {
		return reason, true
	}
	for _, p := range SentinelPrefixes {
		if strings.HasPrefix(match, p) {
			return "matches known sample token prefix " + p, true
		}
	}
	return "", false
}

// shortCircuit returns (verdict, true) if a finding can be decided
// without involving the LLM:
//
//   - any underlying detector returned Verified=true → confirmed (1.0)
//   - the match equals or is prefixed by a known sentinel → dismissed (1.0)
//
// Otherwise it returns (zero, false) and the finding is queued for the
// LLM.
func shortCircuit(d detector.DedupedFinding) (Verdict, bool) {
	if d.AnyVerified {
		return Verdict{
			FindingID:  d.ID,
			Verdict:    VerdictConfirmed,
			Confidence: 1.0,
			Reason:     "live credential verified against provider API",
		}, true
	}
	if reason, ok := classifySentinel(d.Match); ok {
		return Verdict{
			FindingID:  d.ID,
			Verdict:    VerdictDismissed,
			Confidence: 1.0,
			Reason:     reason,
		}, true
	}
	return Verdict{}, false
}
