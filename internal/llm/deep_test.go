package llm

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

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
	// twoFileDiff touches two files, and windows hold one file each.
	if got.Calls != 2 || got.Windows != 2 {
		t.Errorf("Calls=%d Windows=%d, want 2 and 2 (one window per file)", got.Calls, got.Windows)
	}
	if len(client.requests) != 2 {
		t.Fatalf("want 2 requests, got %d", len(client.requests))
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
	if len(client.requests) == 0 {
		t.Error("with a finding present the scan must run, made no calls")
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

// ---- admission and selection ----

// The deep read must never queue behind a busy backend. A held slot
// means "not now": the shallow result goes back to the caller with the
// deep read marked deferred, instead of the whole request 503ing.
func TestDeepReader_DefersWhenBackendBusy(t *testing.T) {
	sem := NewSemaphore(1, 16)
	if err := sem.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer sem.Release()

	client := &fakeDeepClient{}
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.AdmissionWait = 0
	r, err := NewDeepReader(cfg, client, sem)
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatalf("deferral is not an error: %v", err)
	}
	if got.Status != DeepDeferred {
		t.Errorf("Status = %q, want %q", got.Status, DeepDeferred)
	}
	if got.Calls != 0 || len(client.requests) != 0 {
		t.Errorf("a deferred read must make no LLM call, made %d", len(client.requests))
	}
	if got.Windows == 0 {
		t.Error("Windows should still report what would have been scanned")
	}
	if sem.QueueDepth() != 1 {
		t.Errorf("a deferred read must not linger as a waiter: depth=%d, want 1", sem.QueueDepth())
	}
}

// yieldingClient registers an Acquire waiter during its first call and
// blocks until that waiter is queued. When the reader releases the
// slot after window one, the waiter takes it (a blocked sender is
// handed the buffer slot directly on Release) and holds it, like an
// adjudication running a call. The reader's next TryAcquire finds the
// slot busy, waits out its admission budget, and yields: partial.
type yieldingClient struct {
	fakeDeepClient
	sem   *Semaphore
	hold  time.Duration
	once  sync.Once
	freed chan struct{}
}

func (y *yieldingClient) Complete(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	y.once.Do(func() {
		go func() {
			_ = y.sem.Acquire(context.Background())
			time.Sleep(y.hold)
			y.sem.Release()
			close(y.freed)
		}()
		deadline := time.Now().Add(time.Second)
		for y.sem.QueueDepth() < 2 && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
	})
	return y.fakeDeepClient.Complete(ctx, req)
}

func TestDeepReader_YieldsMidScanToWaiter(t *testing.T) {
	sem := NewSemaphore(1, 16)
	client := &yieldingClient{
		fakeDeepClient: fakeDeepClient{replies: []string{
			`{"candidates":[{"value":"found-in-window-one","kind":"credential","confidence":0.9,"reason":"x"}]}`,
		}},
		sem:   sem,
		hold:  300 * time.Millisecond, // longer than the admission wait
		freed: make(chan struct{}),
	}
	cfg := deepTestConfig(t, 32)
	cfg.DeepScan.WindowTokens = 150
	cfg.DeepScan.AdmissionWait = 50 * time.Millisecond
	r, err := NewDeepReader(cfg, client, sem)
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(fillerDiff(40)), 0)
	if err != nil {
		t.Fatal(err)
	}
	<-client.freed

	if got.Status != DeepPartial {
		t.Fatalf("Status = %q, want %q (windows=%d scanned=%d)", got.Status, DeepPartial, got.Windows, got.WindowsScanned)
	}
	if got.WindowsScanned != 1 {
		t.Errorf("WindowsScanned = %d, want 1: must stop as soon as a waiter appears", got.WindowsScanned)
	}
	if got.Windows < 2 {
		t.Errorf("Windows = %d, want the full planned count", got.Windows)
	}
	if len(got.Candidates) != 1 {
		t.Errorf("candidates from the scanned window must be kept, got %d", len(got.Candidates))
	}
}

func TestDeepReader_CompleteStatusOnNormalRun(t *testing.T) {
	client := &fakeDeepClient{}
	r, err := NewDeepReader(deepTestConfig(t, 8), client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != DeepComplete {
		t.Errorf("Status = %q, want %q", got.Status, DeepComplete)
	}
	if got.WindowsScanned != got.Windows {
		t.Errorf("WindowsScanned=%d Windows=%d, want equal on a complete run", got.WindowsScanned, got.Windows)
	}
}

func TestDeepReader_RequireFindingsReportsSkipped(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.RequireFindings = true
	r, err := NewDeepReader(cfg, &fakeDeepClient{}, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != DeepSkipped || got.Reason != "require_findings" {
		t.Errorf("got status=%q reason=%q, want skipped/require_findings", got.Status, got.Reason)
	}
}

func TestDeepReader_MaxAddedLinesSkipsBigDiffs(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.MaxAddedLines = 10
	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	got, err := r.Scan(context.Background(), []byte(fillerDiff(40)), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != DeepSkipped || got.Reason != "max_added_lines" {
		t.Errorf("40 added lines over a cap of 10 must skip, got status=%q reason=%q", got.Status, got.Reason)
	}
	if len(client.requests) != 0 {
		t.Errorf("skipped read must make no calls, made %d", len(client.requests))
	}

	got, err = r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != DeepComplete {
		t.Errorf("3 added lines under a cap of 10 must run, got %q", got.Status)
	}
}

func TestDeepReader_SampleRateSkipsByDraw(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.SampleRate = 0.5
	client := &fakeDeepClient{}
	r, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}

	r.draw = func() float64 { return 0.9 } // above the rate: skip
	got, _ := r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if got.Status != DeepSkipped || got.Reason != "sample_rate" {
		t.Errorf("draw 0.9 at rate 0.5 must skip, got status=%q reason=%q", got.Status, got.Reason)
	}

	r.draw = func() float64 { return 0.1 } // below the rate: run
	got, _ = r.Scan(context.Background(), []byte(twoFileDiff), 0)
	if got.Status != DeepComplete {
		t.Errorf("draw 0.1 at rate 0.5 must run, got %q", got.Status)
	}
}
