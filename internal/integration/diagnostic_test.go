//go:build integration

package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/atalaia/internal/api"
	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/llm"
	"github.com/juanfont/atalaia/internal/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// These records intentionally contain RAW SYNTHETIC credentials. This recorder
// is test-only, requires an explicit destination, and accepts only the checked-in
// corpus or frozen holdout. It is never installed in a production App.
type completionRecord struct {
	Stage     string           `json:"stage"`
	LatencyMS int64            `json:"latency_ms"`
	Request   llm.ChatRequest  `json:"request"`
	Response  llm.ChatResponse `json:"response"`
	Error     string           `json:"error,omitempty"`
}
type diagnosticClient struct {
	llm.ChatCompleter
	thinking string
	records  []completionRecord
}

func (c *diagnosticClient) Complete(ctx context.Context, req llm.ChatRequest) (llm.ChatResponse, error) {
	if c.thinking != "default" {
		req.ChatTemplateKwargs = map[string]any{"enable_thinking": c.thinking == "on"}
	}
	stage := "adjudication"
	if len(req.Tools) > 0 && req.Tools[0].Function.Name == llm.DeepToolName {
		stage = "deep"
	}
	start := time.Now()
	resp, err := c.ChatCompleter.Complete(ctx, req)
	record := completionRecord{Stage: stage, Request: req, Response: resp, LatencyMS: time.Since(start).Milliseconds()}
	if err != nil {
		record.Error = err.Error()
	}
	c.records = append(c.records, record)
	return resp, err
}

type diagnosticAdjudicator struct {
	*llm.Adjudicator
	findings []detector.DedupedFinding
	result   llm.AdjudicateResult
}

func (a *diagnosticAdjudicator) Adjudicate(ctx context.Context, diff []byte, findings []detector.DedupedFinding) (llm.AdjudicateResult, error) {
	a.findings = findings
	result, err := a.Adjudicator.Adjudicate(ctx, diff, findings)
	a.result = result
	return result, err
}

type diagnosticDeep struct {
	*llm.DeepReader
	result llm.DeepResult
}

func (d *diagnosticDeep) Scan(ctx context.Context, diff []byte, n int) (llm.DeepResult, error) {
	result, err := d.DeepReader.Scan(ctx, diff, n)
	d.result = result
	return result, err
}

// TestDiagnosticCorpus runs the REAL /check handler and the SAME assertions as
// TestIntegrationCorpus, adding a recorder around the model and stage seams.
func TestDiagnosticCorpus(t *testing.T) {
	endpoint := os.Getenv("EVAL_ENDPOINT")
	if endpoint == "" {
		t.Skip("EVAL_ENDPOINT not set")
	}
	output := os.Getenv("EVAL_OUTPUT")
	if output == "" {
		t.Fatal("EVAL_OUTPUT is required; records contain synthetic raw values")
	}
	output, err := filepath.Abs(output)
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	set := os.Getenv("EVAL_SET")
	if set == "" {
		set = "diffs"
	}
	if set != "diffs" && set != "holdout" && set != "holdout3" && set != "holdout4" {
		t.Fatal("EVAL_SET must be diffs, holdout, holdout3, or holdout4")
	}
	dir := filepath.Join(root, "internal/integration/testdata", set)
	paths, err := filepath.Glob(filepath.Join(dir, "*.diff"))
	if err != nil || len(paths) == 0 {
		t.Fatal("empty or unreadable fixture set", err)
	}
	names := map[string]string{}
	hashes := map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		key := hex.EncodeToString(sum[:])
		name := strings.TrimSuffix(filepath.Base(p), ".diff")
		names[key] = name
		e, err := os.ReadFile(strings.TrimSuffix(p, ".diff") + ".expect.json")
		if err != nil {
			t.Fatal(err)
		}
		es := sha256.Sum256(e)
		hashes[name] = hex.EncodeToString(es[:])
	}
	t.Chdir(root)
	config := os.Getenv("EVAL_CONFIG")
	if config == "" {
		config = "internal/integration/testdata/eval.yaml"
	}
	if err := types.ReadViperConfig(config, true); err != nil {
		t.Fatal(err)
	}
	cfg, err := types.GetConfig()
	if err != nil {
		t.Fatal(err)
	}
	cfg.LLM.Endpoint = endpoint
	cfg.Server.AuthToken = ""
	// Selection must match a requested complete deep scan for this evaluator.
	cfg.LLM.DeepScan.Enabled = true
	cfg.Observability.Audit.Enabled = false
	thinking := os.Getenv("EVAL_THINKING")
	if thinking == "" {
		thinking = "off"
	}
	if thinking != "on" && thinking != "off" && thinking != "default" {
		t.Fatal("EVAL_THINKING must be on, off, or default")
	}
	client := &diagnosticClient{ChatCompleter: llm.NewClient(endpoint, cfg.LLM.Model, cfg.LLM.RequestTimeout), thinking: thinking}
	adj, err := llm.NewAdjudicator(cfg.LLM, client)
	if err != nil {
		t.Fatal(err)
	}
	deep, err := llm.NewDeepReader(cfg.LLM, client, adj.Semaphore())
	if err != nil {
		t.Fatal(err)
	}
	a := &diagnosticAdjudicator{Adjudicator: adj}
	d := &diagnosticDeep{DeepReader: deep}
	detectors, err := detector.BuildEnabled(cfg.Detectors)
	if err != nil {
		t.Fatal(err)
	}
	previous := log.Logger
	log.Logger = zerolog.Nop()
	t.Cleanup(func() { log.Logger = previous })
	router := mux.NewRouter()
	_, err = api.NewApp(context.Background(), api.Deps{Config: cfg, Detectors: detectors, Adjudicator: a, DeepScanner: d, Router: router})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	encoder := json.NewEncoder(file)
	runs := map[string]int{}
	var mu sync.Mutex
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock() // corpus requests remain sequential on one LLM slot
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read fixture", 400)
			return
		}
		sum := sha256.Sum256(body)
		hash := hex.EncodeToString(sum[:])
		name, ok := names[hash]
		if !ok {
			http.Error(w, "only frozen synthetic fixtures are accepted", 400)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		client.records = nil
		a.findings = nil
		a.result = llm.AdjudicateResult{}
		d.result = llm.DeepResult{}
		start := time.Now()
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, r)
		latency := time.Since(start).Milliseconds()
		var ground []llm.GroundDecision
		if d.result.Status == llm.DeepComplete || d.result.Status == llm.DeepPartial {
			_, _, ground = llm.GroundWithTrace(body, d.result.Candidates, a.findings)
		}
		var response any
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
			t.Errorf("decode API response: %v", err)
		}
		runs[name]++
		record := map[string]any{"name": name, "run": runs[name], "set": set, "thinking": thinking, "latency_ms": latency, "diff_sha256": hash, "expectation_sha256": hashes[name], "model": cfg.LLM.Model, "prompt": adj.PromptFingerprint(), "prompt_deep": deep.PromptFingerprint(), "calls": client.records, "findings": a.findings, "adjudication": a.result, "deep": d.result, "grounding": ground, "response": response, "http_status": rec.Code}
		if err := encoder.Encode(record); err != nil {
			t.Errorf("write diagnostic record: %v", err)
		}
		for k, values := range rec.Header() {
			for _, v := range values {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(rec.Code)
		_, _ = w.Write(rec.Body.Bytes())
	}))
	defer server.Close()
	t.Setenv("ATALAIA_INTEGRATION_URL", server.URL)
	t.Setenv("INTEGRATION_FIXTURES", dir)
	TestIntegrationCorpus(t)
}
