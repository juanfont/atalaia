package llm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/types"
)

// fakeClient is a deterministic ChatCompleter for adjudicate tests.
type fakeClient struct {
	respond func(req ChatRequest) (ChatResponse, error)
	calls   int
}

func (f *fakeClient) Complete(_ context.Context, req ChatRequest) (ChatResponse, error) {
	f.calls++
	return f.respond(req)
}

func (f *fakeClient) Probe(_ context.Context) error { return nil }

func newAdjudicator(t *testing.T, client ChatCompleter) *Adjudicator {
	t.Helper()
	dir := t.TempDir()
	sys := filepath.Join(dir, "sys.tmpl")
	usr := filepath.Join(dir, "usr.tmpl")
	if err := os.WriteFile(sys, []byte("be brief"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(usr, []byte("findings:{{range .Findings}}{{.ID}};{{end}}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := types.LLMConfig{
		Endpoint:              "http://test",
		Model:                 "test-model",
		MaxInflight:           1,
		QueueMax:              4,
		Profile:               "test",
		MaxFindingsPerRequest: 0,
		ContextBudget:         types.ContextBudgetConfig{OutputTokens: 256},
		Profiles: map[string]types.LLMProfile{
			"test": {SystemTemplate: sys, UserTemplate: usr},
		},
	}
	a, err := NewAdjudicator(cfg, client)
	if err != nil {
		t.Fatalf("NewAdjudicator: %v", err)
	}
	return a
}

func TestAdjudicate_AllShortCircuited_SkipsLLM(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		t.Fatal("LLM must not be called when every finding short-circuits")
		return ChatResponse{}, nil
	}}
	a := newAdjudicator(t, fc)
	in := []detector.DedupedFinding{
		{ID: "v1", Match: "AKIAIOSFODNN7EXAMPLE"},
		{ID: "v2", Match: "anything", AnyVerified: true},
	}
	res, err := a.Adjudicate(context.Background(), []byte("diff"), in)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if res.LLMInvoked {
		t.Error("LLMInvoked=true, want false")
	}
	if len(res.Verdicts) != 2 {
		t.Fatalf("verdicts=%d, want 2", len(res.Verdicts))
	}
	if fc.calls != 0 {
		t.Errorf("fake client called %d times, want 0", fc.calls)
	}
}

func TestAdjudicate_CallsLLM_AndMerges(t *testing.T) {
	fc := &fakeClient{respond: func(req ChatRequest) (ChatResponse, error) {
		// echo finding ids back as "confirmed"
		var sysSeen, usrSeen bool
		for _, m := range req.Messages {
			if m.Role == "system" {
				sysSeen = true
			}
			if m.Role == "user" {
				usrSeen = true
			}
		}
		if !sysSeen || !usrSeen {
			return ChatResponse{}, errors.New("expected system+user messages")
		}
		body := `{"verdicts":[
			{"finding_id":"a","verdict":"confirmed","confidence":0.9,"reason":"looks live"},
			{"finding_id":"b","verdict":"dismissed","confidence":0.7,"reason":"test fixture"}
		]}`
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Role: "assistant", Content: body}}}}, nil
	}}
	a := newAdjudicator(t, fc)
	in := []detector.DedupedFinding{
		{ID: "a", Match: "real-secret"},
		{ID: "b", Match: "test_token"},
	}
	res, err := a.Adjudicate(context.Background(), []byte("diff"), in)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !res.LLMInvoked || res.LLMCalls != 1 {
		t.Errorf("LLMInvoked=%v LLMCalls=%d, want true/1", res.LLMInvoked, res.LLMCalls)
	}
	if len(res.Verdicts) != 2 {
		t.Fatalf("verdicts=%d, want 2", len(res.Verdicts))
	}
	verdicts := map[string]Verdict{}
	for _, v := range res.Verdicts {
		verdicts[v.FindingID] = v
	}
	if v := verdicts["a"]; v.Verdict != VerdictConfirmed || v.Confidence < 0.8 {
		t.Errorf("verdict a wrong: %+v", v)
	}
	if v := verdicts["b"]; v.Verdict != VerdictDismissed {
		t.Errorf("verdict b wrong: %+v", v)
	}
}

func TestAdjudicate_GapFilledForMissingVerdict(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		// only return one of the two verdicts
		body, _ := json.Marshal(map[string]any{
			"verdicts": []map[string]any{
				{"finding_id": "a", "verdict": "confirmed", "confidence": 0.5, "reason": "ok"},
			},
		})
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Content: string(body)}}}}, nil
	}}
	a := newAdjudicator(t, fc)
	in := []detector.DedupedFinding{
		{ID: "a", Match: "x"},
		{ID: "b", Match: "y"},
	}
	res, _ := a.Adjudicate(context.Background(), []byte("diff"), in)
	got := map[string]Verdict{}
	for _, v := range res.Verdicts {
		got[v.FindingID] = v
	}
	if got["b"].Verdict != VerdictConfirmed || got["b"].Confidence != 0 {
		t.Errorf("gap-fill produced wrong verdict for b: %+v", got["b"])
	}
	if got["b"].Reason == "" {
		t.Errorf("gap-fill missing reason")
	}
}

func TestAdjudicate_TruncatesAtMaxFindingsPerRequest(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Content: `{"verdicts":[]}`}}}}, nil
	}}
	a := newAdjudicator(t, fc)
	a.maxCount = 2

	in := []detector.DedupedFinding{
		{ID: "a", Match: "1"},
		{ID: "b", Match: "2"},
		{ID: "c", Match: "3"},
	}
	res, err := a.Adjudicate(context.Background(), []byte("diff"), in)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !res.Truncated {
		t.Error("Truncated=false, want true")
	}
	if len(res.Verdicts) != 2 {
		t.Errorf("verdicts=%d, want 2 (truncated input)", len(res.Verdicts))
	}
}

func TestAdjudicate_PerFindingMode_SplitsBatches(t *testing.T) {
	var calls int
	fc := &fakeClient{respond: func(req ChatRequest) (ChatResponse, error) {
		calls++
		// Each batch's user message must NOT contain the whole diff
		// section in per-finding mode (the .Diff field is empty).
		for _, m := range req.Messages {
			if m.Role == "user" && strings.Contains(m.Content, "Diff under review:") {
				t.Errorf("per-finding mode rendered the whole diff section")
			}
		}
		// Echo back verdicts for whichever finding_ids appear in the user message.
		var verdicts []map[string]any
		for _, want := range []string{"id-a", "id-b", "id-c", "id-d"} {
			for _, m := range req.Messages {
				if strings.Contains(m.Content, "finding_id="+want) {
					verdicts = append(verdicts, map[string]any{
						"finding_id": want,
						"verdict":    "dismissed",
						"confidence": 0.7,
						"reason":     "ok",
					})
					break
				}
			}
		}
		body, _ := json.Marshal(map[string]any{"verdicts": verdicts})
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Content: string(body)}}}}, nil
	}}

	a := newAdjudicator(t, fc)
	// Force per-finding mode by setting a tight input budget AND
	// findings whose Match alone bloats well past it.
	a.cfg.ContextBudget.InputTokens = 1024
	a.cfg.ContextBudget.OutputTokens = 128
	a.cfg.ContextBudget.FindingContextLines = 5

	bigMatch := strings.Repeat("z", 4000)
	deduped := []detector.DedupedFinding{
		{ID: "id-a", File: "x.py", Line: 1, Match: bigMatch},
		{ID: "id-b", File: "x.py", Line: 2, Match: bigMatch},
		{ID: "id-c", File: "x.py", Line: 3, Match: bigMatch},
		{ID: "id-d", File: "x.py", Line: 4, Match: bigMatch},
	}
	res, err := a.Adjudicate(context.Background(), []byte("trivial diff"), deduped)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if !res.LLMInvoked {
		t.Fatal("LLMInvoked=false, want true")
	}
	if res.LLMCalls < 2 {
		t.Errorf("LLMCalls=%d, want >=2 (per-finding mode should split)", res.LLMCalls)
	}
	if calls != res.LLMCalls {
		t.Errorf("fakeClient saw %d calls, Result.LLMCalls=%d", calls, res.LLMCalls)
	}
	if len(res.Verdicts) != 4 {
		t.Errorf("verdicts=%d, want 4", len(res.Verdicts))
	}
}

func TestAdjudicate_LLMError_Surfaces(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		return ChatResponse{}, errors.New("backend exploded")
	}}
	a := newAdjudicator(t, fc)
	_, err := a.Adjudicate(context.Background(), []byte("diff"),
		[]detector.DedupedFinding{{ID: "a", Match: "real-token"}})
	if err == nil {
		t.Fatal("expected error from failing LLM call")
	}
}

func TestParseVerdictResponse_StripsCodeFence(t *testing.T) {
	body := "```json\n" + `{"verdicts":[{"finding_id":"a","verdict":"confirmed","confidence":0.5,"reason":"ok"}]}` + "\n```"
	vs, err := parseVerdictResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vs) != 1 || vs[0].FindingID != "a" {
		t.Errorf("got %+v", vs)
	}
}

// Some models (notably small Gemmas without guided decoding) skip the
// {"verdicts": ...} envelope and return a bare top-level array.
// parseVerdictResponse must accept either shape.
func TestParseVerdictResponse_BareArray(t *testing.T) {
	body := "```json\n[{\"finding_id\":\"a\",\"verdict\":\"dismissed\",\"confidence\":0.9,\"reason\":\"placeholder\"}]\n```"
	vs, err := parseVerdictResponse(body)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(vs) != 1 || vs[0].FindingID != "a" || vs[0].Verdict != "dismissed" {
		t.Errorf("got %+v", vs)
	}
}

func TestParseVerdictResponse_RejectsGarbage(t *testing.T) {
	if _, err := parseVerdictResponse("not json at all"); err == nil {
		t.Error("expected error for non-JSON body")
	}
}
