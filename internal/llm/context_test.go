package llm

import (
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
)

func TestEstimateTokens(t *testing.T) {
	if got := estimateTokens(""); got != 0 {
		t.Errorf("empty -> %d, want 0", got)
	}
	// conservative chars/3: (80+2)/3 = 27
	in := strings.Repeat("x", 80)
	if got := estimateTokens(in); got != 27 {
		t.Errorf("80 chars -> %d, want 27", got)
	}
}

const sampleDiff = `diff --git a/keys.py b/keys.py
index aaaaaaa..bbbbbbb 100644
--- a/keys.py
+++ b/keys.py
@@ -1,4 +1,7 @@
 # config
 import os

+# new section
+access_key = "AKIA1234ABCDEFGHIJKL"
+secret = "xyz"
 footer
`

func TestBuildFileIndex(t *testing.T) {
	idx := buildFileIndex([]byte(sampleDiff))
	fl, ok := idx["keys.py"]
	if !ok {
		t.Fatalf("missing keys.py in index; got %+v", idx)
	}
	// Lines in the new file: 1 # config, 2 import os, 3 (blank), 4 # new section,
	// 5 access_key=..., 6 secret="xyz", 7 footer. All 7 are tracked.
	if len(fl.nums) != 7 {
		t.Errorf("index lines=%d, want 7: %+v", len(fl.nums), fl.nums)
	}
	if fl.text[5] != `access_key = "AKIA1234ABCDEFGHIJKL"` {
		t.Errorf("line 5 = %q", fl.text[5])
	}
}

func TestFindingContext_ClampsToWindow(t *testing.T) {
	idx := buildFileIndex([]byte(sampleDiff))
	got := findingContext(idx, "keys.py", 5, 2)
	// expect lines 3..7 with line 5 marked with '>'
	for _, want := range []string{"3:", "4:", "5:", "6:", "7:"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing line %q in context: %q", want, got)
		}
	}
	if !strings.Contains(got, "> ") {
		t.Errorf("context missing finding-line marker: %q", got)
	}
	if strings.Contains(got, " 2:") || strings.Contains(got, " 8:") {
		t.Errorf("context bled past ±2 window: %q", got)
	}
}

func TestFindingContext_UnknownFile(t *testing.T) {
	idx := buildFileIndex([]byte(sampleDiff))
	if got := findingContext(idx, "no-such-file", 1, 5); got != "" {
		t.Errorf("expected empty for unknown file, got %q", got)
	}
}

func TestFitsSingleCall(t *testing.T) {
	findings := []detector.DedupedFinding{
		{ID: "a", File: "a.py", Line: 1, Match: "x"},
	}
	if !fitsSingleCall([]byte("tiny diff"), findings, 4096, 256) {
		t.Error("tiny diff should fit in 4K budget")
	}

	big := []byte(strings.Repeat("x", 4096*4*2)) // ~8K tokens of diff
	if fitsSingleCall(big, findings, 4096, 256) {
		t.Error("8K-token diff should not fit a 4K budget")
	}
}

func TestPackBatches_RespectsBudget(t *testing.T) {
	// Make findings that each render to ~400 chars; budget chosen so
	// ~3 fit per batch.
	bigMatch := strings.Repeat("c", 1500)
	var findings []detector.DedupedFinding
	for i := 0; i < 7; i++ {
		findings = append(findings, detector.DedupedFinding{
			ID: "id" + string(rune('a'+i)), File: "a.py", Line: 1, Match: bigMatch,
		})
	}
	idx := fileIndex{}
	batches := packBatches(findings, idx, 30, 1500, 200)
	if len(batches) < 2 {
		t.Errorf("expected multiple batches for 7 fat findings, got %d", len(batches))
	}
	total := 0
	for _, b := range batches {
		total += len(b)
	}
	if total != 7 {
		t.Errorf("packed %d findings, want 7", total)
	}
}

// A finding with a pathologically large match (e.g. a regex hit on a
// minified line) must be clamped so it can never push a prompt past the
// model's context limit. Every batch must stay within the per-call
// budget, and the giant match must come back bounded.
func TestPackBatches_OversizedFindingClampedToFit(t *testing.T) {
	const inputBudget, outputBudget = 1024, 128
	effective := ((inputBudget - outputBudget) * 9) / 10
	findings := []detector.DedupedFinding{
		{ID: "small", File: "a.py", Line: 1, Match: "x"},
		{ID: "huge", File: "b.py", Line: 1, Match: strings.Repeat("z", 200000)},
		{ID: "tail", File: "c.py", Line: 1, Match: "y"},
	}
	batches := packBatches(findings, fileIndex{}, 30, inputBudget, outputBudget)

	total := 0
	var hugeBody string
	for _, b := range batches {
		total += len(b)
		// Guarantee: no batch exceeds the per-call budget.
		sum := 0
		for _, pf := range b {
			sum += estimateTokens(promptFindingApproxBody(pf))
			if pf.ID == "huge" {
				hugeBody = pf.Match
			}
		}
		if sum > effective {
			t.Errorf("batch over budget: %d tokens > effective %d", sum, effective)
		}
	}
	if total != 3 {
		t.Errorf("packed %d findings, want 3", total)
	}
	if len(hugeBody) > maxMatchChars {
		t.Errorf("huge match not clamped: %d chars > %d", len(hugeBody), maxMatchChars)
	}
}

func TestClampHelpers(t *testing.T) {
	if got := clampStr("short", 100); got != "short" {
		t.Errorf("under-limit clamped: %q", got)
	}
	big := strings.Repeat("a", 5000)
	if got := clampStr(big, maxMatchChars); len(got) > maxMatchChars || !strings.HasSuffix(got, truncMark) {
		t.Errorf("clampStr did not bound+mark: len=%d", len(got))
	}
	mid := clampMiddle(strings.Repeat("x", 1000)+"TAIL", 100)
	if len(mid) > 100 || !strings.Contains(mid, truncMark) {
		t.Errorf("clampMiddle did not bound+mark: len=%d", len(mid))
	}
	if !strings.HasSuffix(mid, "TAIL") {
		t.Errorf("clampMiddle should keep the tail: %q", mid[len(mid)-10:])
	}
}
