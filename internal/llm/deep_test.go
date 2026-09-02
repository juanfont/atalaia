package llm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/juanfont/atalaia/internal/types"
)

type fakeDeepClient struct {
	mu       sync.Mutex
	requests []ChatRequest
	replies  []string
	err      error
}

func (f *fakeDeepClient) Complete(_ context.Context, req ChatRequest) (ChatResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, req)
	if f.err != nil {
		return ChatResponse{}, f.err
	}
	reply := `{"candidates":[]}`
	if len(f.replies) > 0 {
		reply = f.replies[0]
		f.replies = f.replies[1:]
	}
	return chatResponseWith(reply), nil
}

func (f *fakeDeepClient) Probe(context.Context) error { return nil }

func chatResponseWith(content string) ChatResponse {
	var resp ChatResponse
	resp.Choices = append(resp.Choices, struct {
		Message Message `json:"message"`
	}{Message: Message{Role: "assistant", Content: content}})
	return resp
}

func deepTestConfig(t *testing.T, maxWindows int) types.LLMConfig {
	t.Helper()
	return types.LLMConfig{
		Model:    "test-model",
		UseTools: false,
		ContextBudget: types.ContextBudgetConfig{
			InputTokens:  400,
			OutputTokens: 100,
		},
		Profile: "gemma4",
		Profiles: map[string]types.LLMProfile{
			"gemma4_deep": {
				SystemTemplate: "../../prompts/gemma4_deep_system.tmpl",
				UserTemplate:   "../../prompts/gemma4_deep_user.tmpl",
			},
		},
		DeepScan: types.DeepScanConfig{
			Enabled:       true,
			MaxWindows:    maxWindows,
			MaxCandidates: 50,
			Profile:       "gemma4_deep",
		},
	}
}

func TestDeepReader_ScansAndReturnsCandidates(t *testing.T) {
	client := &fakeDeepClient{replies: []string{
		`{"candidates":[{"value":"sk-live-abc123def456","kind":"credential","confidence":0.9,"reason":"api key"}]}`,
	}}
	r, err := NewDeepReader(deepTestConfig(t, 8), client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got.Candidates))
	}
	if got.Calls != 1 || got.Windows != 1 {
		t.Errorf("Calls=%d Windows=%d, want 1 and 1", got.Calls, got.Windows)
	}
	if len(client.requests) != 1 {
		t.Fatalf("want 1 request, got %d", len(client.requests))
	}

	// The deep prompt must not carry detector findings: it is a cold
	// read, and mentioning findings would reintroduce the anchoring the
	// whole feature exists to escape.
	body := client.requests[0].Messages[len(client.requests[0].Messages)-1].Content
	if strings.Contains(body, "finding_id") {
		t.Errorf("deep prompt must not mention findings:\n%s", body)
	}
	if !strings.Contains(body, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("deep prompt should carry the added lines:\n%s", body)
	}
}

func TestDeepReader_NoAddedLinesMakesNoCall(t *testing.T) {
	client := &fakeDeepClient{}
	r, err := NewDeepReader(deepTestConfig(t, 8), client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte("diff --git a/x b/x\n"), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 0 {
		t.Errorf("empty added-line set must make no LLM call, made %d", len(client.requests))
	}
	if got.Calls != 0 {
		t.Errorf("Calls = %d, want 0", got.Calls)
	}
}

func TestDeepReader_RequireFindingsSkipsCleanDiffs(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.RequireFindings = true
	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.Scan(context.Background(), []byte(twoFileDiff), 0); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 0 {
		t.Errorf("require_findings must skip a diff with no findings, made %d calls", len(client.requests))
	}

	if _, err := r.Scan(context.Background(), []byte(twoFileDiff), 1); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) != 1 {
		t.Errorf("with a finding present the scan must run, made %d calls", len(client.requests))
	}
}

func TestDeepReader_PropagatesClientError(t *testing.T) {
	client := &fakeDeepClient{err: errors.New("backend exploded")}
	r, err := NewDeepReader(deepTestConfig(t, 8), client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.Scan(context.Background(), []byte(twoFileDiff), 0); err == nil {
		t.Fatal("want the client error surfaced so the handler can report it")
	}
}

func TestDeepReader_CapsCandidatesPerCall(t *testing.T) {
	var sb strings.Builder
	sb.WriteString(`{"candidates":[`)
	for i := 0; i < 10; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`{"value":"sk-live-abcdef","kind":"credential","confidence":0.5,"reason":"x"}`)
	}
	sb.WriteString(`]}`)

	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.MaxCandidates = 3
	client := &fakeDeepClient{replies: []string{sb.String()}}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Candidates) != 3 {
		t.Errorf("want candidates capped at 3, got %d", len(got.Candidates))
	}
}

func TestDeepReader_ScansEveryWindow(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(fillerDiff(40)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Windows < 2 {
		t.Fatalf("test needs a multi-window diff, got %d", got.Windows)
	}
	if got.Calls != got.Windows {
		t.Errorf("Calls=%d Windows=%d, every window must get its own call", got.Calls, got.Windows)
	}
	if len(client.requests) != got.Windows {
		t.Errorf("made %d requests for %d windows", len(client.requests), got.Windows)
	}
}

func TestDeepReader_EmptyChoicesIsAnError(t *testing.T) {
	client := &emptyChoiceClient{}
	r, err := NewDeepReader(deepTestConfig(t, 8), client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.Scan(context.Background(), []byte(twoFileDiff), 0); err == nil {
		t.Error("a response with no choices must error, not read as clean")
	}
}

type emptyChoiceClient struct{}

func (emptyChoiceClient) Complete(context.Context, ChatRequest) (ChatResponse, error) {
	return ChatResponse{}, nil
}
func (emptyChoiceClient) Probe(context.Context) error { return nil }

// The deep read must use its own window budget, not the adjudication
// context budget. Recall on a buried secret degrades sharply as the
// window grows, so a small window is the whole point.
func TestDeepReader_UsesDeepWindowBudget(t *testing.T) {
	cfg := deepTestConfig(t, 32)
	cfg.ContextBudget.InputTokens = 100000 // adjudication's roomy budget
	cfg.ContextBudget.OutputTokens = 4096
	cfg.DeepScan.WindowTokens = 150 // deep read's deliberately small one

	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(fillerDiff(40)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Windows < 2 {
		t.Errorf("windows=%d: the small deep budget must split this, not the 100k context budget", got.Windows)
	}
}

func TestDeepReader_FallsBackToContextBudget(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.ContextBudget.InputTokens = 400
	cfg.ContextBudget.OutputTokens = 100
	cfg.DeepScan.WindowTokens = 0 // unset

	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := r.Scan(context.Background(), []byte(twoFileDiff), 0); err != nil {
		t.Fatal(err)
	}
	if len(client.requests) == 0 {
		t.Error("unset window_tokens must fall back to the context budget, not scan nothing")
	}
}
