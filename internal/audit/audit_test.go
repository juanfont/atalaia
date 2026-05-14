package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/types"
)

func sampleEntry() Entry {
	return Entry{
		RequestID:    "01H...",
		DiffBytes:    1234,
		DetectorsRun: []string{"gitleaks"},
		RawFindings:  2,
		AfterDedup:   1,
		Confirmed:    1,
		LLMInvoked:   true,
		LLMCalls:     1,
		LLMModel:     "test-model",
		LLMLatencyMs: 1500,
		TotalMs:      1520,
		Verdicts: []Verdict{
			{
				ID:           "abc123",
				File:         "x.py",
				Line:         5,
				MatchPreview: "AKIA****IJKL",
				Match:        "AKIA1234ABCDEFGHIJKL",
				Verdict:      "confirmed",
				Confidence:   0.9,
				Reason:       "live key",
			},
		},
	}
}

func TestFileWriter_WritesJSONLAndTimestamps(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	w, err := NewFileWriter(path)
	if err != nil {
		t.Fatalf("NewFileWriter: %v", err)
	}
	defer w.Close()

	if err := w.Write(sampleEntry()); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := w.Write(sampleEntry()); err != nil {
		t.Fatalf("Write: %v", err)
	}

	f, _ := os.Open(path)
	defer f.Close()
	sc := bufio.NewScanner(f)
	var lines []string
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	var got Entry
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatalf("unmarshal line 0: %v", err)
	}
	if got.RequestID != "01H..." {
		t.Errorf("RequestID=%q", got.RequestID)
	}
	if got.Timestamp == "" {
		t.Error("Timestamp empty; expected auto-fill")
	}
}

func TestNew_DisabledReturnsNop(t *testing.T) {
	w, err := New(types.AuditConfig{Enabled: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, ok := w.(nopWriter); !ok {
		t.Errorf("expected nopWriter when disabled, got %T", w)
	}
}

func TestNew_EnabledNeedsPath(t *testing.T) {
	if _, err := New(types.AuditConfig{Enabled: true, Path: ""}); err == nil {
		t.Error("expected error when enabled with empty path")
	}
}

// The audit redaction policy lives at the call site (api handler):
// callers populate Verdict.Match only when AuditConfig.RevealMatches
// is true. This test pins that contract by ensuring the schema
// supports both shapes round-tripping cleanly.
func TestEntryRoundTrip_OmitsEmptyMatch(t *testing.T) {
	e := sampleEntry()
	e.Verdicts[0].Match = "" // preview-only mode
	b, _ := json.Marshal(e)
	if strings.Contains(string(b), `"match":`) {
		t.Errorf("empty Match should be omitempty, but JSON had it: %s", b)
	}
}
