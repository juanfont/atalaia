package llm

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/atalaia/internal/detector"
)

type recoveryClient struct {
	responses []ChatResponse
	requests  []ChatRequest
	after     func(int, context.Context)
	err       error
}

func (c *recoveryClient) Complete(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	c.requests = append(c.requests, req)
	if c.after != nil {
		c.after(len(c.requests), ctx)
	}
	if c.err != nil {
		return ChatResponse{}, c.err
	}
	if len(c.responses) == 0 {
		return ChatResponse{}, errors.New("unexpected extra request")
	}
	r := c.responses[0]
	c.responses = c.responses[1:]
	return r, nil
}
func (c *recoveryClient) Probe(context.Context) error { return nil }
func completion(content, finish string) ChatResponse {
	r := chatResponseWith(content)
	r.Choices[0].FinishReason = finish
	return r
}

func TestCompletionRecovery(t *testing.T) {
	const valid = `{"candidates":[{"value":"syntheticCredential91","kind":"credential","confidence":1,"reason":"literal"}]}`
	const partial = `{"candidates":[{"value":"discardedPartial93","kind":"credential","confidence":1,"reason":"literal"}]}`
	for _, tc := range []struct {
		name       string
		responses  []ChatResponse
		calls      int
		fail       bool
		candidates int
	}{
		{"malformed", []ChatResponse{completion("broken sensitiveValue77", "stop"), completion(valid, "stop")}, 2, false, 1},
		{"length_even_with_valid_json", []ChatResponse{completion(partial, "length"), completion(valid, "stop")}, 2, false, 1},
		{"no_semantic_retry", []ChatResponse{completion(`{"candidates":[]}`, "stop")}, 1, false, 0},
		{"bounded", []ChatResponse{completion("sensitiveValue77", "stop"), completion("sensitiveValue77", "stop")}, 2, true, 0},
		{"refusal", []ChatResponse{completion(valid, "content_filter")}, 1, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := &recoveryClient{responses: tc.responses}
			req := ChatRequest{MaxTokens: 128, Messages: []Message{{Role: "user", Content: "original input"}}}
			got, calls, err := completeParsed(context.Background(), client, req, func(m Message) ([]DeepCandidate, error) { return parseDeepResponse(m.Content) })
			if (err != nil) != tc.fail || calls != tc.calls || len(client.requests) != tc.calls || len(got) != tc.candidates {
				t.Fatalf("got candidates=%v calls=%d err=%v", got, calls, err)
			}
			if err != nil && strings.Contains(err.Error(), "sensitiveValue77") {
				t.Fatal("error exposed model text")
			}
			if len(got) > 0 && got[0].Value != "syntheticCredential91" {
				t.Fatal("partial response leaked into replacement")
			}
			if len(req.Messages) != 1 || req.Messages[0].Content != "original input" {
				t.Fatal("caller prompt mutated")
			}
			for _, request := range client.requests {
				if request.MaxTokens != 128 {
					t.Fatal("retry expanded output budget")
				}
			}
		})
	}
}
func TestRecoverySharesDeadlineAndHonorsCancellation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	client := &recoveryClient{responses: []ChatResponse{completion("bad", "stop"), completion(`{"candidates":[]}`, "stop")}}
	client.after = func(n int, got context.Context) {
		if d, ok := got.Deadline(); !ok || !d.Equal(deadline) {
			t.Error("retry changed deadline")
		}
	}
	_, calls, err := completeParsed(ctx, client, ChatRequest{}, func(m Message) ([]DeepCandidate, error) { return parseDeepResponse(m.Content) })
	if err != nil || calls != 2 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
	client = &recoveryClient{responses: []ChatResponse{completion("bad", "stop")}, after: func(_ int, _ context.Context) { cancel() }}
	_, calls, err = completeParsed(ctx, client, ChatRequest{}, func(m Message) ([]DeepCandidate, error) { return parseDeepResponse(m.Content) })
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
func TestRecoveryDoesNotRetryTransportErrors(t *testing.T) {
	client := &recoveryClient{err: context.DeadlineExceeded}
	_, calls, err := completeParsed(context.Background(), client, ChatRequest{}, func(m Message) ([]DeepCandidate, error) { return parseDeepResponse(m.Content) })
	if !errors.Is(err, context.DeadlineExceeded) || calls != 1 {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
func TestDeepRecoveryCountsAttemptsAndReleasesSemaphore(t *testing.T) {
	client := &recoveryClient{responses: []ChatResponse{completion("bad", "stop"), completion(`{"candidates":[]}`, "stop")}}
	sem := NewSemaphore(1, 16)
	reader, err := NewDeepReader(deepTestConfig(t, 8), client, sem)
	if err != nil {
		t.Fatal(err)
	}
	diff := []byte("diff --git a/test.txt b/test.txt\n--- /dev/null\n+++ b/test.txt\n@@ -0,0 +1,1 @@\n+hello\n")
	result, err := reader.Scan(context.Background(), diff, 0)
	if err != nil || result.Calls != 2 || result.WindowsScanned != 1 || result.Status != DeepComplete {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if !sem.TryAcquire(context.Background(), 0) {
		t.Fatal("semaphore leaked")
	}
	sem.Release()
	client.responses = []ChatResponse{completion("bad", "length"), completion("bad", "length")}
	result, err = reader.Scan(context.Background(), diff, 0)
	if err == nil || result.Calls != 2 || result.WindowsScanned != 0 {
		t.Fatalf("failed result=%+v err=%v", result, err)
	}
	if !sem.TryAcquire(context.Background(), 0) {
		t.Fatal("semaphore leaked on failure")
	}
	sem.Release()
}

func TestThinkingParametersOptional(t *testing.T) {
	if thinkingParameters(nil) != nil {
		t.Fatal("unspecified thinking must omit the extension")
	}
	for _, enabled := range []bool{false, true} {
		if thinkingParameters(&enabled)["enable_thinking"] != enabled {
			t.Fatal("explicit thinking value lost")
		}
	}
}

func TestConfiguredThinkingAndAdjudicationRecovery(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		client := &recoveryClient{responses: []ChatResponse{completion("malformed", "stop"), completion(`{"verdicts":[{"finding_id":"f1","verdict":"confirmed","confidence":1,"reason":"literal"}]}`, "stop")}}
		a := newAdjudicator(t, client)
		a.cfg.EnableThinking = &enabled
		a.cfg.ContextBudget.InputTokens = 10000
		got, err := a.Adjudicate(context.Background(), []byte("diff"), []detector.DedupedFinding{{ID: "f1", File: "app.py", Line: 1, Match: "opaqueCredential82"}})
		if err != nil || got.LLMCalls != 2 || len(got.Verdicts) != 1 || got.Verdicts[0].Verdict != VerdictConfirmed {
			t.Fatalf("adjudication recovery: %+v %v", got, err)
		}
		for _, req := range client.requests {
			if req.ChatTemplateKwargs["enable_thinking"] != enabled {
				t.Fatal("adjudication thinking override lost")
			}
		}
		client = &recoveryClient{responses: []ChatResponse{completion(`{"candidates":[]}`, "stop")}}
		cfg := deepTestConfig(t, 8)
		cfg.EnableThinking = &enabled
		deep, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
		if err != nil {
			t.Fatal(err)
		}
		_, err = deep.Scan(context.Background(), []byte("diff --git a/a b/a\n--- /dev/null\n+++ b/a\n@@ -0,0 +1,1 @@\n+hello\n"), 0)
		if err != nil || len(client.requests) != 1 || client.requests[0].ChatTemplateKwargs["enable_thinking"] != enabled {
			t.Fatalf("deep thinking override: %v", err)
		}
	}
}
