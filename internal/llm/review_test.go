package llm

import (
	"context"
	"strings"
	"testing"
	"time"
)

func reviewReply(body string) func(ChatRequest) (ChatResponse, error) {
	return func(ChatRequest) (ChatResponse, error) {
		return ChatResponse{Choices: []struct {
			Message      Message `json:"message"`
			FinishReason string  `json:"finish_reason"`
		}{{Message: Message{Role: "assistant", Content: body}}}}, nil
	}
}

func TestReview_KeepsOnlyConfirmed(t *testing.T) {
	var seen string
	fc := &fakeClient{respond: func(req ChatRequest) (ChatResponse, error) {
		seen = req.Messages[1].Content
		return reviewReply(`{"verdicts":[
			{"finding_id":"keep","verdict":"confirmed","confidence":0.8,"reason":"password Tr0ubad0ur-Winter-2026 in a URL"},
			{"finding_id":"drop","verdict":"dismissed","confidence":0.9,"reason":"a sed expression"}
		]}`)(req)
	}}
	a := newAdjudicator(t, fc)
	in := []Discovery{
		{ID: "keep", File: "a.sh", Line: 2, Match: "Tr0ubad0ur-Winter-2026", Kind: "credential", Confidence: 1, Reason: "deep"},
		{ID: "drop", File: "a.sh", Line: 3, Match: "s/x/y/g", Kind: "credential", Confidence: 1, Reason: "deep"},
		{ID: "gone", File: "a.sh", Line: 4, Match: "unanswered-value", Kind: "credential", Confidence: 1, Reason: "deep"},
	}
	res, err := a.Review(context.Background(), []byte("diff"), in, time.Second)
	if err != nil {
		t.Fatalf("Review: %v", err)
	}
	if !strings.Contains(seen, "keep;drop;gone;") {
		t.Errorf("every discovery must be put to the adjudicator, prompt was %q", seen)
	}
	if !res.Admitted || res.Calls != 1 || res.Dismissed != 1 || res.Withheld != 1 || len(res.Kept) != 1 {
		t.Fatalf("result = %+v, want admitted, 1 call, 1 kept, 1 dismissed, 1 withheld", res)
	}
	k := res.Kept[0]
	if k.ID != "keep" || k.Confidence != 0.8 {
		t.Errorf("kept discovery must carry the review confidence: %+v", k)
	}
	if strings.Contains(k.Reason, "Tr0ubad0ur-Winter-2026") {
		t.Errorf("review reason must be scrubbed of the raw value: %q", k.Reason)
	}
}

// Review borrows idle capacity like the deep read. With the only slot
// taken it reports not admitted instead of queueing.
func TestReview_NotAdmittedWhenBusy(t *testing.T) {
	fc := &fakeClient{respond: func(ChatRequest) (ChatResponse, error) {
		t.Fatal("no LLM call without a slot")
		return ChatResponse{}, nil
	}}
	a := newAdjudicator(t, fc)
	if err := a.Semaphore().Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.Semaphore().Release()
	res, err := a.Review(context.Background(), []byte("diff"), []Discovery{{ID: "x", Match: "value-123456"}}, 10*time.Millisecond)
	if err != nil || res.Admitted || len(res.Kept) != 0 {
		t.Errorf("want not admitted and nothing kept, got %+v err=%v", res, err)
	}
}
