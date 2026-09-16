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
// Fixtures pair a unified diff with expected verdicts, discoveries, or
// credentials accepted in either channel. Expanded cases require exact
// added-line locations, cap total alerts and unreviewed findings, and
// reject incomplete coverage. See testdata/README.md for authoring rules,
// tags, contrast pairs, and the distinction between recall and clean scans.
//
// Legacy verdict agreement is scored against INTEGRATION_MIN_AGREEMENT
// (default 0.8). Missing expanded credentials and excess alerts are hard
// failures independently of that aggregate floor.
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
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

func findingID(file string, line int, match string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", file, line, match)))
	return hex.EncodeToString(h[:])[:12]
}

func minAgreement(t *testing.T) float64 {
	t.Helper()
	raw := os.Getenv("INTEGRATION_MIN_AGREEMENT")
	if raw == "" {
		return 0.8
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
	repeat := integrationRepeat(t)
	floor := minAgreement(t)
	fixtureFloor := minFixtureAgreement(t)

	dir := os.Getenv("INTEGRATION_FIXTURES")
	if dir == "" {
		dir = "testdata/diffs"
	}
	entries, err := filepath.Glob(filepath.Join(dir, "*.diff"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(entries) == 0 {
		t.Fatalf("no fixtures under testdata/diffs/")
	}

	var hits, total, selected int
	var secretHits, secretTotal, cleanHits, cleanTotal int
	tagHits, tagTotals := map[string]int{}, map[string]int{}
	for _, diffPath := range entries {
		diffPath := diffPath
		name := strings.TrimSuffix(filepath.Base(diffPath), ".diff")
		t.Run(name, func(t *testing.T) {
			if only := os.Getenv("INTEGRATION_ONLY"); only != "" && !strings.HasPrefix(name, only) {
				t.Skipf("INTEGRATION_ONLY=%s", only)
			}
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
			if tag := os.Getenv("INTEGRATION_TAG"); tag != "" && !hasTag(fx, tag) {
				t.Skipf("INTEGRATION_TAG=%s", tag)
			}
			selected++
			t.Logf("fixture: %s", fx.Description)

			// Each fixture is scanned `repeat` times. A single sample
			// hides the model's residual non-determinism — the kind that
			// turned a ~4% confirm flake into recurring production false
			// positives — so with repeat > 1 we assert a per-fixture
			// agreement rate rather than trusting one verdict.
			var fHits, fTotal int
			dist := map[string]map[string]int{} // match -> verdict label -> count
			for i := 0; i < repeat; i++ {
				resp, err := postCheck(base, token, diff, fx.Deep)
				if err != nil {
					t.Fatalf("run %d: POST /check: %v", i+1, err)
				}
				if hasTag(fx, "expanded") && (resp.Stats.Truncated || len(resp.Stats.DetectorErrors) > 0) {
					t.Errorf("run %d: incomplete detector coverage: truncated=%v failed_detectors=%d", i+1, resp.Stats.Truncated, len(resp.Stats.DetectorErrors))
				}
				for _, limit := range []struct {
					name string
					max  *int
					got  int
				}{
					{"alerts", fx.MaxAlerts, alertCount(resp)},
					{"unreviewed", fx.MaxUnreviewed, resp.Stats.Unreviewed},
				} {
					if limit.max == nil {
						continue
					}
					fTotal++
					if limit.got <= *limit.max {
						fHits++
					} else {
						t.Errorf("run %d: %s=%d exceeds maximum=%d", i+1, limit.name, limit.got, *limit.max)
					}
				}
				if hasTag(fx, "negative") {
					cleanTotal++
					if alertCount(resp) == 0 && resp.Stats.Unreviewed == 0 && completeCoverage(resp) {
						cleanHits++
					}
				}
				for _, want := range fx.ExpectSecrets {
					fTotal++
					secretTotal++
					if foundSecret(resp, want) {
						fHits++
						secretHits++
					} else {
						t.Errorf("run %d: missing credential at %s:%d in confirmed verdicts or discoveries", i+1, want.File, want.Line)
					}
				}
				if resp.Stats.AfterDedup < fx.MinAfterDedup {
					t.Fatalf("run %d: stats.after_dedup=%d, want >= %d (detectors saw fewer findings than the fixture promises)",
						i+1, resp.Stats.AfterDedup, fx.MinAfterDedup)
				}
				if fx.MaxConfirmed != nil && resp.Stats.Confirmed > *fx.MaxConfirmed {
					t.Errorf("run %d: stats.confirmed=%d exceeds max_confirmed=%d (likely gap-fills from too large an LLM batch)",
						i+1, resp.Stats.Confirmed, *fx.MaxConfirmed)
				}
				for _, ex := range fx.Expectations {
					v, ok := findVerdict(resp.Verdicts, ex.Match)
					if !ok {
						// Hard fail: the detector did not flag what the
						// fixture expects. The corpus starts from a
						// finding that the LLM then sorts.
						t.Errorf("run %d: expected match %q not present in response", i+1, ex.Match)
						continue
					}
					label := v.Verdict
					if isGapFill(v) {
						// Gap-fills (model returned no verdict) count
						// against agreement: no useful answer.
						label = "gap-fill"
					}
					if dist[ex.Match] == nil {
						dist[ex.Match] = map[string]int{}
					}
					dist[ex.Match][label]++
					fTotal++
					if !isGapFill(v) && v.Verdict == ex.Verdict {
						fHits++
					}
				}

				if fx.Deep {
					dHits, dTotal := gradeDiscoveries(t, i+1, fx, resp)
					fHits += dHits
					fTotal += dTotal
				}
			}

			for _, ex := range fx.Expectations {
				labels := make([]string, 0, len(dist[ex.Match]))
				for k := range dist[ex.Match] {
					labels = append(labels, k)
				}
				sort.Strings(labels)
				parts := make([]string, len(labels))
				for i, k := range labels {
					parts[i] = fmt.Sprintf("%s=%d", k, dist[ex.Match][k])
				}
				t.Logf("  %q want=%s  [%s]", ex.Match, ex.Verdict, strings.Join(parts, " "))
			}

			hits += fHits
			total += fTotal
			for _, tag := range fx.Tags {
				tagHits[tag] += fHits
				tagTotals[tag] += fTotal
			}
			if fTotal == 0 {
				return
			}
			agree := float64(fHits) / float64(fTotal)
			t.Logf("%s: agreement %.0f%% (%d/%d) over %d run(s), per-fixture floor %.0f%%",
				name, agree*100, fHits, fTotal, repeat, fixtureFloor*100)
			// The per-fixture hard gate only engages under repeated
			// sampling, and it is strict (default 99%): a fixture that
			// flips even occasionally is a real flake to investigate. A
			// single run stays soft (the lenient aggregate gate below
			// catches broad regressions) so fast per-commit CI is
			// unchanged.
			if repeat > 1 && agree < fixtureFloor {
				t.Errorf("fixture %s agreement %.2f below per-fixture floor %.2f over %d runs", name, agree, fixtureFloor, repeat)
			}
		})
	}

	// Aggregate gate. Catches regressions where the prompt gets broadly
	// worse without any single fixture tripping its own threshold.
	if selected == 0 {
		t.Fatal("no fixtures selected; check INTEGRATION_ONLY and INTEGRATION_TAG")
	}
	if secretTotal > 0 {
		t.Logf("expanded secret recall: %d/%d", secretHits, secretTotal)
	}
	if cleanTotal > 0 {
		t.Logf("expanded clean scans: %d/%d", cleanHits, cleanTotal)
	}
	var tags []string
	for tag := range tagTotals {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		t.Logf("tag %s: %d/%d assertions passed", tag, tagHits[tag], tagTotals[tag])
	}
	if total == 0 {
		return
	}
	agreement := float64(hits) / float64(total)
	t.Logf("corpus: %d/%d agree (%.0f%%) across %d fixtures x %d run(s), floor %.0f%%",
		hits, total, agreement*100, selected, repeat, floor*100)
	if agreement < floor {
		t.Errorf("corpus agreement %.2f below floor %.2f", agreement, floor)
	}
}

// integrationRepeat is how many times each fixture is scanned. Default
// 1 (fast CI, single sample). Set INTEGRATION_REPEAT higher (e.g. 20)
// for a nightly or pre-release run that measures per-fixture agreement
// and so catches the model's residual non-determinism instead of
// sampling it once.
func integrationRepeat(t *testing.T) int {
	t.Helper()
	raw := os.Getenv("INTEGRATION_REPEAT")
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 {
		t.Fatalf("INTEGRATION_REPEAT must be a positive integer: %q", raw)
	}
	return n
}

// minFixtureAgreement is the strict per-fixture pass rate enforced under
// repeated sampling (INTEGRATION_REPEAT > 1). Default 0.99: a fixture
// that disagrees with its expected verdict even occasionally is a flake
// worth chasing, not noise to average away. Distinct from
// minAgreement, which is the lenient aggregate floor for single-sample
// per-commit runs. Override with INTEGRATION_MIN_FIXTURE_AGREEMENT.
func minFixtureAgreement(t *testing.T) float64 {
	t.Helper()
	raw := os.Getenv("INTEGRATION_MIN_FIXTURE_AGREEMENT")
	if raw == "" {
		return 0.99
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		t.Fatalf("INTEGRATION_MIN_FIXTURE_AGREEMENT must be a float: %v", err)
	}
	return v
}

// gradeDiscoveries asserts the deep channel on one run and returns
// (hits, total) for the expected-discovery checks.
//
// The two directions are graded differently on purpose. A missing
// expected discovery is scored, not hard-failed: the model misses a
// buried secret a few percent of the time on identical input, so a
// hard gate at one sample per fixture would fail roughly a quarter of
// corpus runs while telling you nothing. Those misses feed the same
// agreement accounting as verdict expectations, so a systematically
// broken deep read still tanks the corpus floor. A false alarm stays a
// hard failure: noise in this channel is what makes it not worth
// reading, and we measured zero.
func gradeDiscoveries(t *testing.T, run int, fx fixture, resp *checkResponse) (hits, total int) {
	t.Helper()

	ds := resp.Stats.DeepScan
	if ds == nil {
		t.Errorf("run %d: fixture is deep but response carried no deep_scan stats", run)
		return 0, 0
	}
	if ds.Error != "" {
		t.Errorf("run %d: deep scan failed: %s", run, ds.Error)
		return 0, 0
	}
	if !ds.Ran || ds.Status != "complete" {
		// The corpus runs against an idle server, so a deferred or
		// partial read here is a bug, not load.
		t.Errorf("run %d: deep scan did not complete: status=%s reason=%q (is llm.deep_scan.enabled set in the config?)",
			run, ds.Status, ds.Reason)
		return 0, 0
	}
	if ds.Truncated {
		t.Errorf("run %d: deep coverage truncated at %d windows", run, ds.Windows)
	}
	t.Logf("run %d: deep windows=%d candidates=%d discovered=%d ungrounded=%d",
		run, ds.Windows, ds.Candidates, ds.Discovered, ds.Ungrounded)

	if fx.MaxDiscoveries != nil && len(resp.Discoveries) > *fx.MaxDiscoveries {
		for _, d := range resp.Discoveries {
			t.Logf("run %d: unexpected discovery %s:%d %s (%s)", run, d.File, d.Line, d.MatchPreview, d.Reason)
		}
		t.Errorf("run %d: %d discoveries exceeds max_discoveries=%d, the deep read is crying wolf",
			run, len(resp.Discoveries), *fx.MaxDiscoveries)
	}

	for _, want := range fx.ExpectDiscoveries {
		total++
		d, ok := findDiscovery(resp.Discoveries, want)
		if !ok {
			t.Logf("run %d: MISS expected discovery %s (the secret no detector flags went unmentioned)",
				run, describeExpectation(want))
			continue
		}
		hits++
		if want.Kind != "" && d.Kind != want.Kind {
			t.Errorf("run %d: discovery %s kind=%q, want %q", run, d.ID, d.Kind, want.Kind)
		}
	}
	return hits, total
}

// findDiscovery locates a discovery matching the expectation. File+line
// wins when given; otherwise it falls back to preview-shape matching on
// the raw value, the same way the verdict path does.
func findDiscovery(discoveries []discovery, want discoveryExpectation) (discovery, bool) {
	if want.File != "" {
		for _, d := range discoveries {
			if d.File == want.File && (want.Line == 0 || d.Line == want.Line) {
				return d, true
			}
		}
		return discovery{}, false
	}
	for _, d := range discoveries {
		if d.MatchPreview == want.Match || previewMatches(d.MatchPreview, want.Match) {
			return d, true
		}
	}
	return discovery{}, false
}

func describeExpectation(want discoveryExpectation) string {
	if want.File != "" {
		return fmt.Sprintf("at %s:%d", want.File, want.Line)
	}
	return fmt.Sprintf("%q", redactForLog(want.Match))
}

// redactForLog keeps expected-secret values out of test output.
func redactForLog(s string) string {
	if len(s) <= 8 {
		return "(short value)"
	}
	return s[:4] + "..." + s[len(s)-4:]
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

func postCheck(base, token string, diff []byte, deep bool) (*checkResponse, error) {
	// A deep request is up to max_windows sequential LLM calls, so it
	// needs a far longer client timeout than the default path.
	timeout := 180 * time.Second
	url := base + "/check"
	if deep {
		timeout = 900 * time.Second
		url += "?deep=1"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(diff))
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
