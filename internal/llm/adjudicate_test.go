package llm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

func TestAdjudicate_UseTools_ParsesToolCallArguments(t *testing.T) {
	fc := &fakeClient{respond: func(req ChatRequest) (ChatResponse, error) {
		// When tools are on, atalaia must send the verdict tool and
		// force tool_choice to submit_verdicts.
		if len(req.Tools) != 1 || req.Tools[0].Function.Name != VerdictToolName {
			t.Errorf("expected one tool=%q, got %+v", VerdictToolName, req.Tools)
		}
		if req.ToolChoice == nil {
			t.Errorf("ToolChoice not set with use_tools")
		}
		// Echo back via a tool_call instead of plain content.
		args := `{"verdicts":[{"finding_id":"a","verdict":"confirmed","confidence":0.9,"reason":"live"}]}`
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{
			Role: "assistant",
			ToolCalls: []ToolCall{{
				ID: "call_1", Type: "function",
				Function: ToolCallFunction{Name: VerdictToolName, Arguments: args},
			}},
		}}}}, nil
	}}

	a := newAdjudicator(t, fc)
	a.cfg.UseTools = true

	res, err := a.Adjudicate(context.Background(), []byte("diff"),
		[]detector.DedupedFinding{{ID: "a", Match: "real-token"}})
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if len(res.Verdicts) != 1 || res.Verdicts[0].FindingID != "a" || res.Verdicts[0].Verdict != VerdictConfirmed {
		t.Errorf("verdicts wrong: %+v", res.Verdicts)
	}
}

func TestAdjudicate_UseTools_MissingToolCallErrors(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		// Model returns plain content even though tools were requested.
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Role: "assistant", Content: "ignored"}}}}, nil
	}}
	a := newAdjudicator(t, fc)
	a.cfg.UseTools = true

	_, err := a.Adjudicate(context.Background(), []byte("diff"),
		[]detector.DedupedFinding{{ID: "a", Match: "x"}})
	if err == nil {
		t.Error("expected error when tools enabled but response has no tool_calls")
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

// newAdjudicatorCap builds an adjudicator with a finding-count cap and a
// generous input budget (so packBatches keeps findings together and the
// count cap is what splits them).
func newAdjudicatorCap(t *testing.T, client ChatCompleter, cap int) *Adjudicator {
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
		Endpoint: "http://test", Model: "test-model", MaxInflight: 1, QueueMax: 4,
		Profile:            "test",
		MaxFindingsPerCall: cap,
		ContextBudget:      types.ContextBudgetConfig{InputTokens: 1_000_000, OutputTokens: 4096, FindingContextLines: 3},
		Profiles:           map[string]types.LLMProfile{"test": {SystemTemplate: sys, UserTemplate: usr}},
	}
	a, err := NewAdjudicator(cfg, client)
	if err != nil {
		t.Fatalf("NewAdjudicator: %v", err)
	}
	return a
}

func TestCapFindingsPerBatch(t *testing.T) {
	mk := func(n int) []PromptFinding {
		fs := make([]PromptFinding, n)
		for i := range fs {
			fs[i] = PromptFinding{ID: fmt.Sprintf("f%d", i)}
		}
		return fs
	}
	// over-cap batch splits into ceil(n/max), Diff preserved, none lost
	out := capFindingsPerBatch([]PromptData{{Diff: "D", Findings: mk(25)}}, 10)
	if len(out) != 3 {
		t.Fatalf("batches=%d, want 3", len(out))
	}
	total := 0
	for _, b := range out {
		if len(b.Findings) > 10 {
			t.Errorf("sub-batch has %d findings, exceeds cap 10", len(b.Findings))
		}
		if b.Diff != "D" {
			t.Errorf("Diff not preserved on split sub-batch")
		}
		total += len(b.Findings)
	}
	if total != 25 {
		t.Errorf("findings lost in split: got %d, want 25", total)
	}
	// exactly cap -> single batch; cap <= 0 -> disabled
	if got := capFindingsPerBatch([]PromptData{{Findings: mk(10)}}, 10); len(got) != 1 {
		t.Errorf("==cap should stay 1 batch, got %d", len(got))
	}
	if got := capFindingsPerBatch([]PromptData{{Findings: mk(100)}}, 0); len(got) != 1 {
		t.Errorf("cap<=0 should not split, got %d batches", len(got))
	}
}

// TestAdjudicate_BatchesByFindingCount is the regression guard for the
// large-commit gap-fill bug: 25 findings with cap 10 must fan out into
// multiple LLM calls of <= 10 each, and every finding must get a real
// verdict (no gap-fills) merged into one result.
func TestAdjudicate_BatchesByFindingCount(t *testing.T) {
	const cap = 10
	fc := &fakeClient{respond: func(req ChatRequest) (ChatResponse, error) {
		ids := idsFromUserMsg(req)
		if len(ids) == 0 {
			return ChatResponse{}, errors.New("no finding ids in user prompt")
		}
		if len(ids) > cap {
			return ChatResponse{}, fmt.Errorf("batch of %d exceeds cap %d", len(ids), cap)
		}
		parts := make([]string, len(ids))
		for i, id := range ids {
			parts[i] = fmt.Sprintf(`{"finding_id":%q,"verdict":"dismissed","confidence":0.9,"reason":"reference"}`, id)
		}
		body := `{"verdicts":[` + strings.Join(parts, ",") + `]}`
		return ChatResponse{Choices: []struct {
			Message Message `json:"message"`
		}{{Message: Message{Role: "assistant", Content: body}}}}, nil
	}}
	a := newAdjudicatorCap(t, fc, cap)

	in := make([]detector.DedupedFinding, 25)
	for i := range in {
		in[i] = detector.DedupedFinding{ID: fmt.Sprintf("f%d", i), File: "x", Line: i + 1, Match: fmt.Sprintf("ref_%d", i)}
	}
	res, err := a.Adjudicate(context.Background(), []byte("diff"), in)
	if err != nil {
		t.Fatalf("Adjudicate: %v", err)
	}
	if res.LLMCalls != 3 {
		t.Errorf("LLMCalls=%d, want 3 (ceil(25/10))", res.LLMCalls)
	}
	if len(res.Verdicts) != 25 {
		t.Fatalf("verdicts=%d, want 25", len(res.Verdicts))
	}
	for _, v := range res.Verdicts {
		if v.Confidence == 0 && strings.HasPrefix(v.Reason, "model returned no verdict") {
			t.Errorf("gap-fill for %s — batching should have given every finding a real verdict", v.FindingID)
		}
		if v.Verdict != VerdictDismissed {
			t.Errorf("verdict %s = %q, want dismissed", v.FindingID, v.Verdict)
		}
	}
}

func idsFromUserMsg(req ChatRequest) []string {
	var content string
	for _, m := range req.Messages {
		if m.Role == "user" {
			content = m.Content
		}
	}
	const p = "findings:"
	i := strings.Index(content, p)
	if i < 0 {
		return nil
	}
	var ids []string
	for _, s := range strings.Split(content[i+len(p):], ";") {
		if s = strings.TrimSpace(s); s != "" {
			ids = append(ids, s)
		}
	}
	return ids
}
