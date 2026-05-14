package detector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadDiff(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "diffs", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func TestWalkDiff_SingleFile(t *testing.T) {
	blocks := WalkDiff(loadDiff(t, "aws_sentinel.diff"))
	if len(blocks) != 1 {
		t.Fatalf("blocks=%d, want 1: %+v", len(blocks), blocks)
	}
	b := blocks[0]
	if b.Path != "example.py" {
		t.Errorf("Path=%q, want example.py", b.Path)
	}
	// Hunk header is @@ -1,3 +1,5 @@; lines 1,2 are context, line 3 is
	// removed, then the first added line is new-file line 3.
	if b.StartLine != 3 {
		t.Errorf("StartLine=%d, want 3", b.StartLine)
	}
	if !strings.Contains(b.Content, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Content missing AWS sentinel: %q", b.Content)
	}
	if !strings.Contains(b.Content, "wJalrXUtnFEMI") {
		t.Errorf("Content missing AWS secret: %q", b.Content)
	}
}

func TestWalkDiff_MultiFile(t *testing.T) {
	blocks := WalkDiff(loadDiff(t, "multi_file.diff"))
	// Expect: one block in src/db.py and one block in README.md.
	// The /dev/null deletion contributes nothing.
	if len(blocks) != 2 {
		t.Fatalf("blocks=%d, want 2", len(blocks))
	}

	byPath := map[string]AddedBlock{}
	for _, b := range blocks {
		byPath[b.Path] = b
	}
	db, ok := byPath["src/db.py"]
	if !ok {
		t.Fatalf("missing src/db.py block; got %+v", blocks)
	}
	// Hunk @@ -10,3 +10,5 @@: context line at 10, blank at 11,
	// removed (no advance), added DSN at 12.
	if db.StartLine != 12 {
		t.Errorf("src/db.py StartLine=%d, want 12", db.StartLine)
	}
	if !strings.Contains(db.Content, "postgresql://admin:s3cret@db.example.com") {
		t.Errorf("src/db.py missing DSN: %q", db.Content)
	}

	readme, ok := byPath["README.md"]
	if !ok {
		t.Fatalf("missing README.md block")
	}
	if readme.StartLine != 1 {
		t.Errorf("README.md StartLine=%d, want 1", readme.StartLine)
	}
}

func TestLocateInDiff(t *testing.T) {
	diff := loadDiff(t, "multi_file.diff")
	file, line := locateInDiff(diff, "AKIAIOSFODNN7EXAMPLE")
	if file != "src/db.py" {
		t.Errorf("file=%q, want src/db.py", file)
	}
	// AWS_KEY follows DSN+blank line, so it's two lines below the DSN start (12 + 2 = 14).
	if line != 14 {
		t.Errorf("line=%d, want 14", line)
	}

	if file, line := locateInDiff(diff, "no-such-secret"); file != "" || line != 0 {
		t.Errorf("expected empty result for missing needle, got (%q, %d)", file, line)
	}
}
