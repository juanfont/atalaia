//go:build integration

// Package integration runs Atalaia end-to-end against a real LLM.
//
// The suite is gated behind the `integration` build tag and the
// ATALAIA_INTEGRATION_URL env var so it never runs from `go test ./...`.
// Invoke via `make smoke-corpus` or directly:
//
//	ATALAIA_INTEGRATION_URL=http://127.0.0.1:8080 \
//	  go test -tags=integration -count=1 ./internal/integration
//
// Each fixture pairs a unified-diff file with an `.expect.json` that
// names per-match expected verdicts. The test POSTs the diff, matches
// the response verdicts back to expectations by raw match (via the
// `finding_id`, which is sha256(file:line:match)[:12]), and reports
// agreement.
//
// Hard fails:
//   - non-2xx from /check
//   - response has fewer dedup'd findings than min_after_dedup
//   - any expected match is missing from the response
//
// Soft fails (per-fixture log, summary failure at end): the verdict
// for a given match disagrees with expectations, or atalaia gap-fills
// because the model returned no verdict for that finding_id. The
// suite fails if overall agreement drops below INTEGRATION_MIN_AGREEMENT
// (default 0.75). Qwen2.5-7B-Instruct-AWQ scores 6/6 cleanly on every
// observed run with the schema-example prompt; smaller models will
// gap-fill more and may warrant a lower floor via env override.
package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

type expectation struct {
	Match   string `json:"match"`
	Verdict string `json:"verdict"`
}

type fixture struct {
	Description   string        `json:"description"`
	MinAfterDedup int           `json:"min_after_dedup"`
	Expectations  []expectation `json:"expectations"`
}

type verdict struct {
	ID           string  `json:"id"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	MatchPreview string  `json:"match_preview"`
	Verdict      string  `json:"verdict"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

type checkResponse struct {
	RequestID string    `json:"request_id"`
	Verdicts  []verdict `json:"verdicts"`
	Stats     struct {
		AfterDedup int  `json:"after_dedup"`
		Confirmed  int  `json:"confirmed"`
		Dismissed  int  `json:"dismissed"`
		LLMInvoked bool `json:"llm_invoked"`
	} `json:"stats"`
}

func findingID(file string, line int, match string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", file, line, match)))
	return hex.EncodeToString(h[:])[:12]
}

func minAgreement(t *testing.T) float64 {
	t.Helper()
	raw := os.Getenv("INTEGRATION_MIN_AGREEMENT")
	if raw == "" {
		return 0.75
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("INTEGRATION_MIN_AGREEMENT must be a float: %v", err)
	}
	return v
}

func TestIntegrationCorpus(t *testing.T) {
	base := os.Getenv("ATALAIA_INTEGRATION_URL")
	if base == "" {
		t.Skip("ATALAIA_INTEGRATION_URL not set; skipping corpus")
	}
	base = strings.TrimRight(base, "/")
	token := os.Getenv("ATALAIA_INTEGRATION_TOKEN")

	entries, err := filepath.Glob("testdata/diffs/*.diff")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no fixtures under testdata/diffs/")
	}

	var hits, misses, gapFills, total int
	for _, diffPath := range entries {
		diffPath := diffPath
		name := strings.TrimSuffix(filepath.Base(diffPath), ".diff")
		t.Run(name, func(t *testing.T) {
			diff, err := os.ReadFile(diffPath)
			if err != nil {
				t.Fatalf("read diff: %v", err)
			}
			expectPath := strings.TrimSuffix(diffPath, ".diff") + ".expect.json"
			raw, err := os.ReadFile(expectPath)
			if err != nil {
				t.Fatalf("read expect: %v", err)
			}
			var fx fixture
			if err := json.Unmarshal(raw, &fx); err != nil {
				t.Fatalf("parse expect: %v", err)
			}
			t.Logf("fixture: %s", fx.Description)

			resp, err := postCheck(base, token, diff)
			if err != nil {
				t.Fatalf("POST /check: %v", err)
			}

			if resp.Stats.AfterDedup < fx.MinAfterDedup {
				t.Fatalf("stats.after_dedup=%d, want >= %d (detectors saw fewer findings than the fixture promises)",
					resp.Stats.AfterDedup, fx.MinAfterDedup)
			}

			// Match expectations to verdicts by the deterministic ID.
			// We have to walk the response to find the (file, line) the
			// detector chose for each match; tests assert on the verdict
			// at that ID.
			byMatchPreview := map[string]verdict{}
			byID := map[string]verdict{}
			for _, v := range resp.Verdicts {
				byID[v.ID] = v
				byMatchPreview[previewKey(v.MatchPreview)] = v
			}

			for _, ex := range fx.Expectations {
				v, ok := findVerdict(resp.Verdicts, ex.Match)
				if !ok {
					// Hard fail: the detector did not flag what the
					// fixture expects. The corpus is meant to start
					// with a finding that the LLM then sorts.
					t.Errorf("expected match %q not present in response", ex.Match)
					continue
				}
				total++
				switch {
				case isGapFill(v):
					gapFills++
					t.Logf("gap-fill: %q -> %s (model returned no verdict, atalaia filled %q)",
						ex.Match, v.Verdict, v.Reason)
				case v.Verdict == ex.Verdict:
					hits++
					t.Logf("agree:    %q -> %s (conf=%.2f, %q)", ex.Match, v.Verdict, v.Confidence, v.Reason)
				default:
					misses++
					// Soft fail: log, but don't t.Errorf. Small models
					// disagree sometimes; the aggregate-agreement gate
					// at the end of the suite is the real signal.
					t.Logf("disagree: %q -> got %s, want %s (conf=%.2f, %q)",
						ex.Match, v.Verdict, ex.Verdict, v.Confidence, v.Reason)
				}
			}
		})
	}

	// Overall agreement gate. Catches regressions where the prompt
	// gets noticeably worse without any single fixture failing hard.
	// Gap-fills count against agreement (the model produced no
	// useful answer).
	if total == 0 {
		return
	}
	agreement := float64(hits) / float64(total)
	floor := minAgreement(t)
	t.Logf("corpus: %d hits, %d misses, %d gap-fills out of %d (agreement %.0f%%, floor %.0f%%)",
		hits, misses, gapFills, total, agreement*100, floor*100)
	if agreement < floor {
		t.Errorf("corpus agreement %.2f below floor %.2f", agreement, floor)
	}
}

// isGapFill recognises the conservative fallback the adjudicator
// emits when the model returned no verdict for a given finding_id
// (see internal/llm/adjudicate.go: confidence 0, fixed reason).
func isGapFill(v verdict) bool {
	return v.Confidence == 0 && strings.HasPrefix(v.Reason, "model returned no verdict")
}

// findVerdict locates the response verdict whose match appears to
// correspond to the expectation's raw match. Detectors emit different
// match shapes (some emit just the secret, some the surrounding
// "key = value" line, gitleaks emits the secret group), so we try a
// few shapes.
func findVerdict(verdicts []verdict, raw string) (verdict, bool) {
	// 1. exact match against preview (only true when raw is short
	// enough not to be redacted, e.g. short tokens)
	for _, v := range verdicts {
		if v.MatchPreview == raw {
			return v, true
		}
	}
	// 2. head+tail of preview against raw. Preview format is
	// "<head4>****<tail4>" for opaque strings.
	for _, v := range verdicts {
		if previewMatches(v.MatchPreview, raw) {
			return v, true
		}
	}
	return verdict{}, false
}

func previewMatches(preview, raw string) bool {
	const mask = "****"
	idx := strings.Index(preview, mask)
	if idx < 0 {
		return preview == raw
	}
	head := preview[:idx]
	tail := preview[idx+len(mask):]
	if head == "" && tail == "" {
		return raw != ""
	}
	if !strings.HasPrefix(raw, head) {
		return false
	}
	if !strings.HasSuffix(raw, tail) {
		return false
	}
	return true
}

func previewKey(p string) string { return p }

func postCheck(base, token string, diff []byte) (*checkResponse, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/check", bytes.NewReader(diff))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "text/x-diff")
	if token != "" {
		req.Header.Set("authorization", "Bearer "+token)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, body)
	}
	var out checkResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("decode: %w (body=%s)", err, body)
	}
	return &out, nil
}
