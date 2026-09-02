package llm

import (
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
)

const groundDiff = `diff --git a/app.go b/app.go
--- a/app.go
+++ b/app.go
@@ -1,1 +1,6 @@
 package main
+const apiKey = "sk-live-9f8a7b6c5d4e3f2a1b0c"
+const fromEnv = os.Getenv("DB_PASSWORD")
+const sample = "AKIAIOSFODNN7EXAMPLE"
+const spaced = "  padded-secret-value  "
`

func cand(v string) DeepCandidate {
	return DeepCandidate{Value: v, Kind: "credential", Confidence: 0.9, Reason: "looks like a key"}
}

func TestGround_DropsHallucinatedValue(t *testing.T) {
	got, stats := Ground([]byte(groundDiff), []DeepCandidate{cand("sk-live-THIS-WAS-NEVER-IN-THE-DIFF")}, nil)

	if len(got) != 0 {
		t.Errorf("a value absent from the diff must not survive: %+v", got)
	}
	if stats.Ungrounded != 1 {
		t.Errorf("Ungrounded = %d, want 1", stats.Ungrounded)
	}
}

func TestGround_LocatesRealValue(t *testing.T) {
	got, stats := Ground([]byte(groundDiff), []DeepCandidate{cand("sk-live-9f8a7b6c5d4e3f2a1b0c")}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 discovery, got %d", len(got))
	}
	d := got[0]
	if d.File != "app.go" {
		t.Errorf("File = %q, want app.go", d.File)
	}
	if d.Line != 2 {
		t.Errorf("Line = %d, want 2", d.Line)
	}
	if d.ID == "" {
		t.Error("discovery needs a stable id")
	}
	if strings.Contains(d.MatchPreview, "9f8a7b6c5d4e3f2a1b0c") {
		t.Errorf("preview must be redacted, got %q", d.MatchPreview)
	}
	if stats.Discovered != 1 {
		t.Errorf("Discovered = %d, want 1", stats.Discovered)
	}
}

func TestGround_NormalizesBeforeGivingUp(t *testing.T) {
	for name, value := range map[string]string{
		"quoted":        `"sk-live-9f8a7b6c5d4e3f2a1b0c"`,
		"trailingComma": "sk-live-9f8a7b6c5d4e3f2a1b0c,",
		"padded":        "  sk-live-9f8a7b6c5d4e3f2a1b0c  ",
		"backticked":    "`sk-live-9f8a7b6c5d4e3f2a1b0c`",
	} {
		t.Run(name, func(t *testing.T) {
			got, _ := Ground([]byte(groundDiff), []DeepCandidate{cand(value)}, nil)
			if len(got) != 1 {
				t.Fatalf("normalization failed for %s: got %d discoveries", name, len(got))
			}
			if got[0].Line != 2 {
				t.Errorf("Line = %d, want 2", got[0].Line)
			}
		})
	}
}

func TestGround_DropsReferences(t *testing.T) {
	for _, v := range []string{"$DB_PASSWORD", "${DB_PASSWORD}", `os.Getenv("DB_PASSWORD")`} {
		got, _ := Ground([]byte(groundDiff), []DeepCandidate{cand(v)}, nil)
		if len(got) != 0 {
			t.Errorf("reference %q must not become a discovery: %+v", v, got)
		}
	}
}

func TestGround_DropsShortValues(t *testing.T) {
	got, _ := Ground([]byte(groundDiff), []DeepCandidate{cand("main")}, nil)
	if len(got) != 0 {
		t.Errorf("trivially short value must not survive: %+v", got)
	}
}

func TestGround_DropsSentinel(t *testing.T) {
	got, stats := Ground([]byte(groundDiff), []DeepCandidate{cand("AKIAIOSFODNN7EXAMPLE")}, nil)

	if len(got) != 0 {
		t.Errorf("known sentinel must be dropped cold too: %+v", got)
	}
	if stats.Discovered != 0 {
		t.Errorf("Discovered = %d, want 0", stats.Discovered)
	}
}

func TestGround_DropsCollisionWithVerdict(t *testing.T) {
	taken := []detector.DedupedFinding{{
		ID:    detector.FindingID(detector.Finding{File: "app.go", Line: 2, Match: "sk-live-9f8a7b6c5d4e3f2a1b0c"}),
		File:  "app.go",
		Line:  2,
		Match: "sk-live-9f8a7b6c5d4e3f2a1b0c",
	}}

	got, stats := Ground([]byte(groundDiff), []DeepCandidate{cand("sk-live-9f8a7b6c5d4e3f2a1b0c")}, taken)

	if len(got) != 0 {
		t.Errorf("a secret already in verdicts[] must not also be a discovery: %+v", got)
	}
	if stats.Collisions != 1 {
		t.Errorf("Collisions = %d, want 1", stats.Collisions)
	}
}

// The detector matched the bare key; the model returned the whole
// assignment. Different ids, same secret, same line. Containment must
// catch it or the response reports one secret in two channels.
func TestGround_DropsOverlappingCollision(t *testing.T) {
	taken := []detector.DedupedFinding{{
		ID:    "detectorid001",
		File:  "app.go",
		Line:  2,
		Match: "sk-live-9f8a7b6c5d4e3f2a1b0c",
	}}
	wider := DeepCandidate{
		Value:      `const apiKey = "sk-live-9f8a7b6c5d4e3f2a1b0c"`,
		Kind:       "credential",
		Confidence: 0.9,
		Reason:     "hardcoded key",
	}

	got, stats := Ground([]byte(groundDiff), []DeepCandidate{wider}, taken)

	if len(got) != 0 {
		t.Errorf("overlapping match on the same line must collide: %+v", got)
	}
	if stats.Collisions != 1 {
		t.Errorf("Collisions = %d, want 1", stats.Collisions)
	}
}

func TestGround_DedupesAcrossWindows(t *testing.T) {
	c := cand("sk-live-9f8a7b6c5d4e3f2a1b0c")
	got, stats := Ground([]byte(groundDiff), []DeepCandidate{c, c}, nil)

	if len(got) != 1 {
		t.Errorf("same secret twice must collapse to one: %+v", got)
	}
	if stats.Discovered != 1 {
		t.Errorf("Discovered = %d, want 1", stats.Discovered)
	}
}

func TestGround_ScrubsReasonOfRawValue(t *testing.T) {
	c := DeepCandidate{
		Value:      "sk-live-9f8a7b6c5d4e3f2a1b0c",
		Kind:       "credential",
		Confidence: 0.9,
		Reason:     "the literal sk-live-9f8a7b6c5d4e3f2a1b0c is a live key",
	}
	got, _ := Ground([]byte(groundDiff), []DeepCandidate{c}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 discovery, got %d", len(got))
	}
	if strings.Contains(got[0].Reason, "sk-live-9f8a7b6c5d4e3f2a1b0c") {
		t.Errorf("raw value leaked through the reason: %q", got[0].Reason)
	}
}

const pemDiff = `diff --git a/id_rsa b/id_rsa
--- /dev/null
+++ b/id_rsa
@@ -0,0 +1,4 @@
+-----BEGIN OPENSSH PRIVATE KEY-----
+b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdz
+c2gtcn0AAAADAQABAAABgQDZ1234567890abcdefghijklmnopqrstuvwxyzAAAA
+-----END OPENSSH PRIVATE KEY-----
`

func TestGround_PrivateKeyGroundsOnHeader(t *testing.T) {
	c := DeepCandidate{
		Value:      "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...truncated by the model...\n-----END OPENSSH PRIVATE KEY-----",
		Kind:       "private_key",
		Reason:     "an OpenSSH private key",
		Confidence: 0.95,
	}

	got, _ := Ground([]byte(pemDiff), []DeepCandidate{c}, nil)

	if len(got) != 1 {
		t.Fatalf("private key must ground on its header line, got %d", len(got))
	}
	if got[0].Line != 1 {
		t.Errorf("Line = %d, want 1", got[0].Line)
	}
	if got[0].Kind != "private_key" {
		t.Errorf("Kind = %q, want private_key", got[0].Kind)
	}
}

// An unknown kind string from a non-schema-enforcing backend must not
// ride through into the response.
func TestGround_NormalizesUnknownKind(t *testing.T) {
	c := DeepCandidate{Value: "sk-live-9f8a7b6c5d4e3f2a1b0c", Kind: "banana", Confidence: 0.5, Reason: "x"}
	got, _ := Ground([]byte(groundDiff), []DeepCandidate{c}, nil)

	if len(got) != 1 {
		t.Fatalf("want 1 discovery, got %d", len(got))
	}
	if got[0].Kind != "credential" {
		t.Errorf("Kind = %q, want it normalized to credential", got[0].Kind)
	}
}

func TestGround_NoCandidatesIsClean(t *testing.T) {
	got, stats := Ground([]byte(groundDiff), nil, nil)
	if len(got) != 0 {
		t.Errorf("no candidates means no discoveries, got %+v", got)
	}
	if stats.Candidates != 0 || stats.Discovered != 0 || stats.Ungrounded != 0 {
		t.Errorf("stats should be zero, got %+v", stats)
	}
}

// The model returned only the END delimiter of a PEM block. It locates
// fine, but it is a marker, not key material, and reporting it would
// surface the same key a second time alongside the detector's verdict.
func TestGround_DropsPemEndMarkerOnly(t *testing.T) {
	c := DeepCandidate{
		Value:      "-----END OPENSSH PRIVATE KEY-----",
		Kind:       "private_key",
		Confidence: 0.9,
		Reason:     "an SSH private key block",
	}

	got, stats := Ground([]byte(pemDiff), []DeepCandidate{c}, nil)

	if len(got) != 0 {
		t.Errorf("an END delimiter is not a credential: %+v", got)
	}
	if stats.Ungrounded != 1 {
		t.Errorf("Ungrounded = %d, want 1", stats.Ungrounded)
	}
}
