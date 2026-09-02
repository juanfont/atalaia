package llm

import (
	"strings"
	"testing"
)

const twoFileDiff = `diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,2 +1,4 @@
 package main
+const key = "AKIAIOSFODNN7EXAMPLE"
+const other = 1
-const gone = "removed-secret-value"
diff --git a/b.go b/b.go
--- a/b.go
+++ b/b.go
@@ -10,1 +10,2 @@
 var x int
+var y = "second-file-value"
`

func TestBuildDeepWindows_AddedLinesOnly(t *testing.T) {
	got, truncated := buildDeepWindows([]byte(twoFileDiff), 72000, 8)

	if truncated {
		t.Errorf("small diff must not truncate")
	}
	if len(got) != 1 {
		t.Fatalf("want 1 window, got %d", len(got))
	}
	body := got[0]

	if !strings.Contains(body, `const key = "AKIAIOSFODNN7EXAMPLE"`) {
		t.Errorf("added line missing from window:\n%s", body)
	}
	if !strings.Contains(body, "second-file-value") {
		t.Errorf("second file's added line missing:\n%s", body)
	}
	if strings.Contains(body, "removed-secret-value") {
		t.Errorf("removed line must never be scanned:\n%s", body)
	}
	if strings.Contains(body, "package main") {
		t.Errorf("context line must not be scanned:\n%s", body)
	}
	if !strings.Contains(body, "a.go") || !strings.Contains(body, "b.go") {
		t.Errorf("window must name both files:\n%s", body)
	}
}

func fillerDiff(lines int) string {
	var sb strings.Builder
	sb.WriteString("diff --git a/big.go b/big.go\n--- a/big.go\n+++ b/big.go\n@@ -1,1 +1,500 @@\n")
	for i := 0; i < lines; i++ {
		sb.WriteString("+// filler line with enough text to consume budget\n")
	}
	return sb.String()
}

func TestBuildDeepWindows_SplitsAcrossWindows(t *testing.T) {
	// 40 filler lines at a 150-token budget is roughly 4 windows, well
	// inside the cap, so this isolates splitting from truncation.
	got, truncated := buildDeepWindows([]byte(fillerDiff(40)), 150, 8)

	if len(got) < 2 {
		t.Fatalf("want the block split across windows, got %d", len(got))
	}
	if truncated {
		t.Errorf("8 windows is enough for 40 lines, should not truncate")
	}
	for i, w := range got {
		if !strings.Contains(w, "big.go") {
			t.Errorf("window %d lost its file header:\n%s", i, w)
		}
	}
}

func TestBuildDeepWindows_TruncatesAtMaxWindows(t *testing.T) {
	got, truncated := buildDeepWindows([]byte(fillerDiff(500)), 150, 2)

	if len(got) != 2 {
		t.Errorf("want exactly max_windows windows, got %d", len(got))
	}
	if !truncated {
		t.Error("dropping coverage must set truncated")
	}
}

func TestBuildDeepWindows_EmptyDiff(t *testing.T) {
	got, truncated := buildDeepWindows([]byte("diff --git a/x b/x\n"), 72000, 8)
	if len(got) != 0 {
		t.Errorf("no added lines means no windows, got %d", len(got))
	}
	if truncated {
		t.Error("nothing to scan is not truncation")
	}
}

// Every added line must land in some window. A packer that drops the
// tail would silently shrink coverage, which is the failure this whole
// feature exists to prevent.
func TestBuildDeepWindows_LosesNoAddedLine(t *testing.T) {
	got, truncated := buildDeepWindows([]byte(fillerDiff(200)), 150, 0)
	if truncated {
		t.Fatal("max_windows 0 means uncapped, should not truncate")
	}

	total := 0
	for _, w := range got {
		total += strings.Count(w, "// filler line")
	}
	if total != 200 {
		t.Errorf("packed %d added lines, want all 200", total)
	}
}
