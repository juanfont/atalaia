package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/atalaia/apitypes"
	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/llm"
	"github.com/juanfont/atalaia/internal/types"
)

// fakeAdjudicator is a deterministic stand-in for the API tests. It
// returns one "confirmed" verdict per finding by default and lets the
// test override Adjudicate behavior. Probe is unused by /readyz now
// (the Reachability watcher owns reachability) but stays on the
// interface to satisfy *llm.Adjudicator.
type fakeAdjudicator struct {
	probeErr     error
	adjudicate   func(deduped []detector.DedupedFinding) (llm.AdjudicateResult, error)
	captureFinds *[]detector.DedupedFinding
}

func (f *fakeAdjudicator) Probe(_ context.Context) error { return f.probeErr }

func (f *fakeAdjudicator) PromptFingerprint() string { return "test:000000000000" }

// fakeReachability lets a test pin the cached readiness state.
type fakeReachability struct{ ready bool }

func (f fakeReachability) Ready() bool { return f.ready }

func (f *fakeAdjudicator) Adjudicate(_ context.Context, _ []byte, deduped []detector.DedupedFinding) (llm.AdjudicateResult, error) {
	if f.captureFinds != nil {
		*f.captureFinds = append(*f.captureFinds, deduped...)
	}
	if f.adjudicate != nil {
		return f.adjudicate(deduped)
	}
	verdicts := make([]llm.Verdict, len(deduped))
	for i, d := range deduped {
		verdicts[i] = llm.Verdict{
			FindingID:  d.ID,
			Verdict:    llm.VerdictConfirmed,
			Confidence: 0.5,
			Reason:     "fake",
		}
	}
	return llm.AdjudicateResult{
		Result: llm.Result{
			Verdicts:   verdicts,
			LLMInvoked: len(verdicts) > 0,
			LLMCalls:   1,
			LLMLatency: 7 * time.Millisecond,
		},
	}, nil
}

func newTestServer(t *testing.T, adj Adjudicator) *httptest.Server {
	// Default reachability matches the previous /readyz behavior:
	// "ready" unless the test explicitly says otherwise. Use
	// newTestServerWithReachability for the not-ready case.
	return newTestServerWithReachability(t, adj, fakeReachability{ready: true})
}

func newTestServerWithReachability(t *testing.T, adj Adjudicator, r Reachability) *httptest.Server {
	t.Helper()
	cfg := &types.Config{
		Server:    types.ServerConfig{MaxBodyBytes: 1 << 20},
		Detectors: types.DetectorsConfig{Enabled: []string{"gitleaks"}},
		LLM:       types.LLMConfig{Model: "test-model"},
	}
	g, err := detector.NewGitleaks(cfg.Detectors.Gitleaks)
	if err != nil {
		t.Fatalf("gitleaks: %v", err)
	}

	router := mux.NewRouter()
	if _, err := NewApp(context.Background(), Deps{
		Config:       cfg,
		Detectors:    []detector.Detector{g},
		Adjudicator:  adj,
		Reachability: r,
		Version:      "test",
		Router:       router,
	}); err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return httptest.NewServer(router)
}

func loadFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return b
}

func TestCheck_RawDiff(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()

	body := loadFixture(t, "sample.diff")
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}

	var out apitypes.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.RequestID == "" {
		t.Errorf("missing request_id")
	}
	if len(out.Verdicts) == 0 {
		t.Fatalf("expected at least one verdict, got 0")
	}
	for _, v := range out.Verdicts {
		if v.Verdict != apitypes.VerdictConfirmed {
			t.Errorf("verdict=%q, want confirmed (fake adjudicator)", v.Verdict)
		}
		if v.MatchPreview == "AKIA1234ABCDEFGHIJKL" {
			t.Errorf("match_preview leaked raw match: %q", v.MatchPreview)
		}
		if !strings.Contains(v.MatchPreview, "****") {
			t.Errorf("match_preview missing mask: %q", v.MatchPreview)
		}
		if len(v.Detections) == 0 {
			t.Errorf("verdict missing detections trail: %+v", v)
		}
	}
	if !out.Stats.LLMInvoked {
		t.Errorf("Stats.LLMInvoked=false, want true")
	}
	if out.Stats.LLMCalls != 1 {
		t.Errorf("Stats.LLMCalls=%d, want 1", out.Stats.LLMCalls)
	}
	if out.Stats.Confirmed != len(out.Verdicts) {
		t.Errorf("Stats.Confirmed=%d, want %d", out.Stats.Confirmed, len(out.Verdicts))
	}
}

func TestCheck_JSONBody(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()

	diff := string(loadFixture(t, "sample.diff"))
	reqBody, _ := json.Marshal(apitypes.CheckRequest{Diff: diff})
	resp, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestCheck_IDStableAcrossRequests(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	body := loadFixture(t, "sample.diff")

	post := func() apitypes.CheckResponse {
		resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(body))
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		defer resp.Body.Close()
		var out apitypes.CheckResponse
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return out
	}

	a, b := post(), post()
	if a.RequestID == b.RequestID {
		t.Errorf("request_id should differ across requests, got %q twice", a.RequestID)
	}
	if len(a.Verdicts) != len(b.Verdicts) {
		t.Fatalf("verdict count differs: %d vs %d", len(a.Verdicts), len(b.Verdicts))
	}
	for i := range a.Verdicts {
		if a.Verdicts[i].ID != b.Verdicts[i].ID {
			t.Errorf("verdict[%d].id not stable: %q vs %q", i, a.Verdicts[i].ID, b.Verdicts[i].ID)
		}
	}
}

func TestCheck_AcceptsXRequestIDHeader(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/check", bytes.NewReader(loadFixture(t, "sample.diff")))
	req.Header.Set("Content-Type", "text/x-diff")
	req.Header.Set("X-Request-ID", "trace-abc.123:99")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got != "trace-abc.123:99" {
		t.Errorf("response X-Request-ID=%q, want caller-supplied", got)
	}
	var out apitypes.CheckResponse
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.RequestID != "trace-abc.123:99" {
		t.Errorf("body request_id=%q, want caller-supplied", out.RequestID)
	}
}

func TestCheck_RejectsMalformedXRequestID(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	// net/http refuses to put control chars or newlines on the wire,
	// so these cases all exercise the server-side validator on inputs
	// the client will actually send.
	cases := []string{
		"has spaces inside",
		"has/slash",
		"has=equals",
		"has(parens)",
		strings.Repeat("a", 200),
	}
	for _, raw := range cases {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/check", bytes.NewReader(loadFixture(t, "sample.diff")))
		req.Header.Set("Content-Type", "text/x-diff")
		req.Header.Set("X-Request-ID", raw)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST: %v", err)
		}
		got := resp.Header.Get("X-Request-ID")
		resp.Body.Close()
		if got == raw {
			t.Errorf("malformed X-Request-ID %q echoed back; should have been replaced with ULID", raw)
		}
		if got == "" {
			t.Errorf("response missing X-Request-ID for malformed input %q", raw)
		}
	}
}

func TestCheck_EmptyBody(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty body status=%d, want 400", resp.StatusCode)
	}
}

func TestCheck_QueueFullReturns503(t *testing.T) {
	adj := &fakeAdjudicator{
		adjudicate: func([]detector.DedupedFinding) (llm.AdjudicateResult, error) {
			return llm.AdjudicateResult{}, llm.ErrQueueFull
		},
	}
	srv := newTestServer(t, adj)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(loadFixture(t, "sample.diff")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", resp.StatusCode)
	}
}

func TestCheck_LLMErrorReturns502(t *testing.T) {
	adj := &fakeAdjudicator{
		adjudicate: func([]detector.DedupedFinding) (llm.AdjudicateResult, error) {
			return llm.AdjudicateResult{}, errors.New("upstream boom")
		},
	}
	srv := newTestServer(t, adj)
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(loadFixture(t, "sample.diff")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("status=%d, want 502", resp.StatusCode)
	}
}

func TestHealthz_AlwaysOK(t *testing.T) {
	// /healthz is the liveness probe — it should stay 200 even when
	// the LLM is unreachable so orchestrators don't restart the pod
	// over an upstream blip.
	srv := newTestServerWithReachability(t, &fakeAdjudicator{}, fakeReachability{ready: false})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200 (liveness independent of LLM)", resp.StatusCode)
	}
}

func TestReadyz_OK(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	var h apitypes.HealthzResponse
	if err := json.NewDecoder(resp.Body).Decode(&h); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !h.LLMReachable {
		t.Errorf("LLMReachable=false, want true")
	}
}

func TestReadyz_LLMUnreachable(t *testing.T) {
	srv := newTestServerWithReachability(t, &fakeAdjudicator{}, fakeReachability{ready: false})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/readyz")
	if err != nil {
		t.Fatalf("GET /readyz: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status=%d, want 503", resp.StatusCode)
	}
}

func newAuthedServer(t *testing.T, token string) *httptest.Server {
	t.Helper()
	cfg := &types.Config{
		Server:    types.ServerConfig{MaxBodyBytes: 1 << 20, AuthToken: token},
		Detectors: types.DetectorsConfig{Enabled: []string{"gitleaks"}},
		LLM:       types.LLMConfig{Model: "test-model"},
	}
	g, err := detector.NewGitleaks(cfg.Detectors.Gitleaks)
	if err != nil {
		t.Fatalf("gitleaks: %v", err)
	}
	router := mux.NewRouter()
	if _, err := NewApp(context.Background(), Deps{
		Config:       cfg,
		Detectors:    []detector.Detector{g},
		Adjudicator:  &fakeAdjudicator{},
		Reachability: fakeReachability{ready: true},
		Version:      "test",
		Router:       router,
	}); err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return httptest.NewServer(router)
}

func TestAuth_NoTokenConfigured_StaysOpen(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(loadFixture(t, "sample.diff")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, want 200 (no token configured -> open)", resp.StatusCode)
	}
}

func TestAuth_MissingHeader_Returns401(t *testing.T) {
	srv := newAuthedServer(t, "s3cret-token")
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/check", "text/x-diff", bytes.NewReader(loadFixture(t, "sample.diff")))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got == "" {
		t.Errorf("missing WWW-Authenticate header on 401")
	}
}

func TestAuth_WrongToken_Returns401(t *testing.T) {
	srv := newAuthedServer(t, "s3cret-token")
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/check", bytes.NewReader(loadFixture(t, "sample.diff")))
	req.Header.Set("Content-Type", "text/x-diff")
	req.Header.Set("Authorization", "Bearer wrong-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status=%d, want 401", resp.StatusCode)
	}
}

func TestAuth_CorrectToken_PassesThrough(t *testing.T) {
	srv := newAuthedServer(t, "s3cret-token")
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/check", bytes.NewReader(loadFixture(t, "sample.diff")))
	req.Header.Set("Content-Type", "text/x-diff")
	req.Header.Set("Authorization", "Bearer s3cret-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status=%d, want 200", resp.StatusCode)
	}
}

func TestAuth_HealthzAndReadyzStayOpen(t *testing.T) {
	srv := newAuthedServer(t, "s3cret-token")
	defer srv.Close()
	for _, path := range []string{"/healthz", "/readyz", "/version"} {
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusUnauthorized {
			t.Errorf("%s returned 401; orchestrator probes must stay open", path)
		}
	}
}

func TestVersion(t *testing.T) {
	srv := newTestServer(t, &fakeAdjudicator{})
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatalf("GET /version: %v", err)
	}
	defer resp.Body.Close()
	var v apitypes.VersionResponse
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if v.Atalaia != "test" {
		t.Errorf("Atalaia=%q, want test", v.Atalaia)
	}
	if v.LLMModel != "test-model" {
		t.Errorf("LLMModel=%q, want test-model", v.LLMModel)
	}
}

// stubDetector is a test detector with controllable output. It spawns
// nothing; it just returns whatever the test wires up.
type stubDetector struct {
	name string
	find []detector.Finding
	err  error
}

func (s stubDetector) Name() string { return s.name }
func (s stubDetector) Scan(context.Context, []byte) ([]detector.Finding, error) {
	return s.find, s.err
}

func newTestServerWithDetectors(t *testing.T, adj Adjudicator, dets ...detector.Detector) *httptest.Server {
	t.Helper()
	cfg := &types.Config{
		Server:    types.ServerConfig{MaxBodyBytes: 1 << 20},
		Detectors: types.DetectorsConfig{Enabled: []string{"stub"}},
		LLM:       types.LLMConfig{Model: "test-model"},
	}
	router := mux.NewRouter()
	if _, err := NewApp(context.Background(), Deps{
		Config:       cfg,
		Detectors:    dets,
		Adjudicator:  adj,
		Reachability: fakeReachability{ready: true},
		Version:      "test",
		Router:       router,
	}); err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return httptest.NewServer(router)
}

// A scan where every detector failed and nothing was found must not
// report a false "clean": it returns a retryable 503, not 200.
func TestCheck_InconclusiveScanReturns503(t *testing.T) {
	srv := newTestServerWithDetectors(t, &fakeAdjudicator{},
		stubDetector{name: "trufflehog", err: errors.New("signal: killed")})
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/check", "text/x-diff", strings.NewReader("diff --git a/x b/x\n+secret\n"))
	if err != nil {
		t.Fatalf("POST /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d, want 503; body=%s", resp.StatusCode, raw)
	}
	raw, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(raw), "trufflehog") {
		t.Errorf("503 body should name the failed detector; got %s", raw)
	}
}

// A partial failure (one detector errors, another finds something)
// must still return 200 with verdicts, and surface the failure in
// stats.detector_errors so the caller knows the scan was incomplete.
func TestCheck_PartialFailureSurfacesInStats(t *testing.T) {
	found := []detector.Finding{{
		DetectorType: "gitleaks", DetectorName: "generic", File: "x", Line: 1, Match: "AKIA1234ABCDEFGHIJKL",
	}}
	srv := newTestServerWithDetectors(t, &fakeAdjudicator{},
		stubDetector{name: "gitleaks", find: found},
		stubDetector{name: "trufflehog", err: errors.New("signal: killed")})
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/check", "text/x-diff", strings.NewReader("diff --git a/x b/x\n+AKIA1234ABCDEFGHIJKL\n"))
	if err != nil {
		t.Fatalf("POST /check: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("status=%d, want 200; body=%s", resp.StatusCode, raw)
	}
	var out apitypes.CheckResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out.Stats.DetectorErrors) != 1 || out.Stats.DetectorErrors[0].Detector != "trufflehog" {
		t.Fatalf("want one detector_errors entry for trufflehog, got %+v", out.Stats.DetectorErrors)
	}
	if len(out.Verdicts) == 0 {
		t.Errorf("partial failure should still report the finding gitleaks produced")
	}
}

func TestCountVerdicts_CountsUnreviewedSeparately(t *testing.T) {
	vs := []apitypes.Verdict{
		{Verdict: apitypes.VerdictConfirmed},
		{Verdict: apitypes.VerdictDismissed},
		{Verdict: apitypes.VerdictDismissed},
		{Verdict: apitypes.VerdictUnreviewed},
		{Verdict: apitypes.VerdictUnreviewed},
	}
	c, d, u := countVerdicts(vs)
	if c != 1 || d != 2 || u != 2 {
		t.Errorf("countVerdicts = (%d,%d,%d), want (1,2,2)", c, d, u)
	}
	// An unreviewed gap-fill must NOT inflate the confirmed count — that
	// was the bug that turned model hiccups into 'confirmed credential'
	// alerts.
	if c != 1 {
		t.Errorf("unreviewed leaked into confirmed: confirmed=%d", c)
	}
}

// fakeDeepScanner stands in for *llm.DeepReader. It returns candidates
// verbatim; the handler is responsible for grounding them, which is
// what these tests exercise.
type fakeDeepScanner struct {
	result llm.DeepResult
	err    error
	calls  int
}

func (f *fakeDeepScanner) Scan(_ context.Context, _ []byte, _ int) (llm.DeepResult, error) {
	f.calls++
	return f.result, f.err
}

func (f *fakeDeepScanner) PromptFingerprint() string { return "gemma4_deep:abc123" }

// apiDeepDiff is the reported quirk in miniature, with both premises
// verified against gitleaks: DATABASE_PASSWORD fires generic-api-key,
// and the password inside the curl URL fires nothing at all. So the
// detector channel sees one finding and the real leak is invisible to
// it.
const apiDeepDiff = `diff --git a/config/settings.py b/config/settings.py
--- a/config/settings.py
+++ b/config/settings.py
@@ -10,1 +10,2 @@
 DEBUG = False
+DATABASE_PASSWORD = "Xk7pQm2vRt9wZs4yBn6hLd3fJc8gVa5e"
diff --git a/scripts/reindex.sh b/scripts/reindex.sh
--- a/scripts/reindex.sh
+++ b/scripts/reindex.sh
@@ -1,1 +1,2 @@
 #!/bin/sh
+RESULT=$(curl -sS https://svc:Tr0ubad0ur-Winter-2026@search.example.internal/_reindex)
`

// deepURLPassword is the credential in apiDeepDiff that no detector
// flags: the whole point of the deep channel.
const deepURLPassword = "Tr0ubad0ur-Winter-2026"

func newDeepTestServer(t *testing.T, deep DeepScanner) *httptest.Server {
	t.Helper()
	cfg := &types.Config{
		Server:    types.ServerConfig{MaxBodyBytes: 1 << 20},
		Detectors: types.DetectorsConfig{Enabled: []string{"gitleaks"}},
		LLM:       types.LLMConfig{Model: "test-model"},
	}
	g, err := detector.NewGitleaks(cfg.Detectors.Gitleaks)
	if err != nil {
		t.Fatalf("gitleaks: %v", err)
	}

	router := mux.NewRouter()
	if _, err := NewApp(context.Background(), Deps{
		Config:       cfg,
		Detectors:    []detector.Detector{g},
		Adjudicator:  &fakeAdjudicator{},
		DeepScanner:  deep,
		Reachability: fakeReachability{ready: true},
		Version:      "test",
		Router:       router,
	}); err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	return httptest.NewServer(router)
}

func postDeepCheck(t *testing.T, srv *httptest.Server, diff string, deep bool) (*http.Response, apitypes.CheckResponse) {
	t.Helper()
	url := srv.URL + "/check"
	if deep {
		url += "?deep=1"
	}
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(diff))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/x-diff")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out apitypes.CheckResponse
	if res.StatusCode == http.StatusOK {
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatalf("decode: %v; body=%s", err, body)
		}
	}
	return res, out
}

func TestCheck_NoDeepFlagMakesNoDeepCall(t *testing.T) {
	deep := &fakeDeepScanner{}
	srv := newDeepTestServer(t, deep)
	defer srv.Close()

	res, resp := postDeepCheck(t, srv, apiDeepDiff, false)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if deep.calls != 0 {
		t.Errorf("default path must not deep scan, made %d calls", deep.calls)
	}
	if resp.Discoveries != nil {
		t.Errorf("discoveries must be absent without deep: %+v", resp.Discoveries)
	}
	if resp.Stats.DeepScan != nil {
		t.Errorf("deep_scan stats must be absent without deep: %+v", resp.Stats.DeepScan)
	}
}

func TestCheck_DeepFlagReturnsDiscoveries(t *testing.T) {
	deep := &fakeDeepScanner{result: llm.DeepResult{
		Candidates: []llm.DeepCandidate{{
			Value:      deepURLPassword,
			Kind:       "credential",
			Confidence: 0.9,
			Reason:     "basic-auth password embedded in a URL",
		}},
		Calls:   1,
		Windows: 1,
	}}
	srv := newDeepTestServer(t, deep)
	defer srv.Close()

	res, resp := postDeepCheck(t, srv, apiDeepDiff, true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if deep.calls != 1 {
		t.Fatalf("deep scan should have run once, ran %d", deep.calls)
	}
	if len(resp.Discoveries) != 1 {
		t.Fatalf("want 1 discovery, got %d (%+v)", len(resp.Discoveries), resp.Discoveries)
	}
	d := resp.Discoveries[0]
	if d.File != "scripts/reindex.sh" || d.Line != 2 {
		t.Errorf("discovery mislocated: %+v", d)
	}
	if strings.Contains(d.MatchPreview, deepURLPassword) {
		t.Errorf("raw value in response: %q", d.MatchPreview)
	}
	// The detector finding and the discovery are different secrets in
	// different files. Both must be reported, in their own channels.
	if len(resp.Verdicts) != 1 {
		t.Errorf("want the detector finding still in verdicts[], got %d", len(resp.Verdicts))
	}
	if resp.Stats.DeepScan == nil || !resp.Stats.DeepScan.Ran {
		t.Fatalf("deep_scan stats must report ran: %+v", resp.Stats.DeepScan)
	}
	if resp.Stats.DeepScan.Discovered != 1 {
		t.Errorf("Discovered = %d, want 1", resp.Stats.DeepScan.Discovered)
	}
}

// The anti-hallucination gate, end to end through the handler.
func TestCheck_DeepHallucinationIsDropped(t *testing.T) {
	deep := &fakeDeepScanner{result: llm.DeepResult{
		Candidates: []llm.DeepCandidate{{
			Value:      "sk-live-THIS-IS-NOT-IN-THE-DIFF",
			Kind:       "credential",
			Confidence: 0.99,
			Reason:     "very confident and completely made up",
		}},
		Calls:   1,
		Windows: 1,
	}}
	srv := newDeepTestServer(t, deep)
	defer srv.Close()

	_, resp := postDeepCheck(t, srv, apiDeepDiff, true)
	if len(resp.Discoveries) != 0 {
		t.Errorf("invented value must not reach the caller: %+v", resp.Discoveries)
	}
	if resp.Stats.DeepScan.Ungrounded != 1 {
		t.Errorf("Ungrounded = %d, want 1", resp.Stats.DeepScan.Ungrounded)
	}
}

func TestCheck_DeepFailureDoesNotFailRequest(t *testing.T) {
	deep := &fakeDeepScanner{err: errors.New("backend exploded")}
	srv := newDeepTestServer(t, deep)
	defer srv.Close()

	res, resp := postDeepCheck(t, srv, apiDeepDiff, true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("deep failure must not fail the request, got %d", res.StatusCode)
	}
	if len(resp.Verdicts) == 0 {
		t.Error("verdicts must survive a deep failure")
	}
	if resp.Stats.DeepScan == nil || resp.Stats.DeepScan.Error == "" {
		t.Error("deep failure must be reported in stats, never silently absent")
	}
	if resp.Stats.DeepScan.Ran {
		t.Error("a failed deep scan must not report ran")
	}
}

// Deep scan disabled by the operator: the request succeeds and says so,
// rather than answering as though the scan happened.
func TestCheck_DeepDisabledReportsNotRan(t *testing.T) {
	srv := newDeepTestServer(t, nil)
	defer srv.Close()

	res, resp := postDeepCheck(t, srv, apiDeepDiff, true)
	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if resp.Stats.DeepScan == nil {
		t.Fatal("a deep request must always carry deep_scan stats")
	}
	if resp.Stats.DeepScan.Ran {
		t.Error("disabled deep scan must report ran: false")
	}
}

func TestCheck_DeepFlagViaJSONBody(t *testing.T) {
	deep := &fakeDeepScanner{}
	srv := newDeepTestServer(t, deep)
	defer srv.Close()

	body, err := json.Marshal(apitypes.CheckRequest{Diff: apiDeepDiff, Deep: true})
	if err != nil {
		t.Fatal(err)
	}
	res, err := http.Post(srv.URL+"/check", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		t.Fatalf("status %d", res.StatusCode)
	}
	if deep.calls != 1 {
		t.Errorf("deep flag in the JSON body must trigger the scan, calls=%d", deep.calls)
	}
}

func TestVersion_ReportsDeepPromptFingerprint(t *testing.T) {
	srv := newDeepTestServer(t, &fakeDeepScanner{})
	defer srv.Close()

	res, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var v apitypes.VersionResponse
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.PromptDeep != "gemma4_deep:abc123" {
		t.Errorf("PromptDeep = %q, want the deep fingerprint", v.PromptDeep)
	}
}

func TestVersion_OmitsDeepFingerprintWhenDisabled(t *testing.T) {
	srv := newDeepTestServer(t, nil)
	defer srv.Close()

	res, err := http.Get(srv.URL + "/version")
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()

	var v apitypes.VersionResponse
	if err := json.NewDecoder(res.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.PromptDeep != "" {
		t.Errorf("PromptDeep = %q, want empty when deep scan is off", v.PromptDeep)
	}
}
