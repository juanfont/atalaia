package detector

import (
	"context"
	"testing"

	"github.com/juanfont/atalaia/internal/types"
)

func TestGitleaks_DetectsRealLookingKey(t *testing.T) {
	// gitleaks's default ruleset explicitly allowlists the canonical
	// AWS example values (AKIAIOSFODNN7EXAMPLE et al), so the gitleaks
	// scan test uses a synthetic-but-non-sentinel key instead.
	g, err := NewGitleaks(types.GitleaksConfig{})
	if err != nil {
		t.Fatalf("NewGitleaks: %v", err)
	}
	findings, err := g.Scan(context.Background(), loadDiff(t, "real_key.diff"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding for AKIA1234ABCDEFGHIJKL")
	}

	var saw bool
	for _, f := range findings {
		if f.DetectorType != "gitleaks" {
			t.Errorf("DetectorType=%q, want gitleaks", f.DetectorType)
		}
		if f.Match == "AKIA1234ABCDEFGHIJKL" {
			saw = true
			if f.File != "keys.py" {
				t.Errorf("File=%q, want keys.py", f.File)
			}
			// hunk @@ -1,2 +1,4 @@: lines 1-2 context, then "+" blank
			// at new-file line 3, then access_key at new-file line 4.
			if f.Line != 4 {
				t.Errorf("Line=%d, want 4", f.Line)
			}
		}
	}
	if !saw {
		t.Errorf("did not see expected key in findings: %+v", findings)
	}
}

// TestGitleaks_AggressiveConfig guards the shipped gitleaks-aggressive.toml:
// it must load (so [extend] + our rule parse), catch a low-entropy /
// special-character secret the default ruleset misses, and still fire
// the inherited default rules.
func TestGitleaks_AggressiveConfig(t *testing.T) {
	const cfg = "../../gitleaks-aggressive.toml"

	// password value: low entropy AND a special char (backslash). The
	// default ruleset misses it on both counts; the aggressive config
	// must catch it.
	lowEntropy := []byte(`diff --git a/conf.yml b/conf.yml
new file mode 100644
--- /dev/null
+++ b/conf.yml
@@ -0,0 +1,2 @@
+    username: juanfont
+    password: a324kj\#ikodsfsjsdkfhksdf
`)

	def, err := NewGitleaks(types.GitleaksConfig{})
	if err != nil {
		t.Fatalf("default: %v", err)
	}
	aggr, err := NewGitleaks(types.GitleaksConfig{Config: cfg})
	if err != nil {
		t.Fatalf("load aggressive config %q: %v", cfg, err)
	}

	if fs, _ := def.Scan(context.Background(), lowEntropy); len(fs) != 0 {
		t.Errorf("baseline assumption broken: default config flagged the low-entropy password: %+v", fs)
	}

	fs, err := aggr.Scan(context.Background(), lowEntropy)
	if err != nil {
		t.Fatalf("aggressive scan: %v", err)
	}
	var saw bool
	for _, f := range fs {
		if f.Match == `a324kj\#ikodsfsjsdkfhksdf` {
			saw = true
		}
	}
	if !saw {
		t.Errorf("aggressive config did not catch the low-entropy password; findings=%+v", fs)
	}

	// Inherited default rules still fire.
	if fs, _ := aggr.Scan(context.Background(), loadDiff(t, "real_key.diff")); len(fs) == 0 {
		t.Error("aggressive config lost the inherited default rules (real_key.diff found nothing)")
	}
}

func TestGitleaks_SentinelIsAllowlistedByDefault(t *testing.T) {
	// Documents the assumption baked into the milestone-4 short-circuit
	// design: gitleaks's default config already filters known sample
	// values, so we don't need a separate sentinel check at the
	// detector layer for these particular values.
	g, err := NewGitleaks(types.GitleaksConfig{})
	if err != nil {
		t.Fatalf("NewGitleaks: %v", err)
	}
	findings, err := g.Scan(context.Background(), loadDiff(t, "aws_sentinel.diff"))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	for _, f := range findings {
		if f.Match == "AKIAIOSFODNN7EXAMPLE" || f.Match == "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY" {
			t.Errorf("gitleaks unexpectedly matched documented sentinel %q", f.Match)
		}
	}
}
