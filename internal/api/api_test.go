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
