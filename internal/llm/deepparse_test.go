package llm

import "testing"

func TestParseDeepResponse_Envelope(t *testing.T) {
	got, err := parseDeepResponse(`{"candidates":[
		{"value":"sk-live-abc123","kind":"credential","confidence":0.9,"reason":"api key"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
	if got[0].Value != "sk-live-abc123" {
		t.Errorf("Value = %q", got[0].Value)
	}
	if got[0].Kind != "credential" {
		t.Errorf("Kind = %q", got[0].Kind)
	}
	if got[0].Confidence != 0.9 {
		t.Errorf("Confidence = %v", got[0].Confidence)
	}
}

func TestParseDeepResponse_BareArray(t *testing.T) {
	got, err := parseDeepResponse(`[{"value":"sk-live-abc123","kind":"credential","confidence":0.8,"reason":"x"}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
}

// Most diffs contain nothing. An empty answer is the common case and
// must never fail a request.
func TestParseDeepResponse_EmptyIsNotAnError(t *testing.T) {
	for _, raw := range []string{`{"candidates":[]}`, `[]`, ``, `   `, `{}`} {
		got, err := parseDeepResponse(raw)
		if err != nil {
			t.Errorf("raw %q: unexpected error %v", raw, err)
		}
		if len(got) != 0 {
			t.Errorf("raw %q: want no candidates, got %d", raw, len(got))
		}
	}
}

func TestParseDeepResponse_FencedJSON(t *testing.T) {
	got, err := parseDeepResponse("```json\n{\"candidates\":[{\"value\":\"sk-live-abc123\",\"kind\":\"credential\",\"confidence\":0.7,\"reason\":\"x\"}]}\n```")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate through the fence, got %d", len(got))
	}
}

func TestParseDeepResponse_DropsEmptyValues(t *testing.T) {
	got, err := parseDeepResponse(`{"candidates":[{"value":"","kind":"credential","confidence":0.9,"reason":"x"},{"value":"   ","kind":"credential","confidence":0.9,"reason":"y"}]}`)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a candidate with no value is not a claim, got %d", len(got))
	}
}

func TestParseDeepResponse_GarbageErrors(t *testing.T) {
	if _, err := parseDeepResponse("I could not find any secrets, sorry!"); err == nil {
		t.Error("prose must be reported as a parse failure, not silently treated as clean")
	}
}

func TestParseDeepToolCalls(t *testing.T) {
	calls := []ToolCall{{
		Type: "function",
		Function: ToolCallFunction{
			Name:      DeepToolName,
			Arguments: `{"candidates":[{"value":"sk-live-abc123","kind":"credential","confidence":0.9,"reason":"api key"}]}`,
		},
	}}
	got, err := parseDeepToolCalls(calls)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 candidate, got %d", len(got))
	}
}

func TestParseDeepToolCalls_IgnoresOtherTools(t *testing.T) {
	calls := []ToolCall{{
		Type:     "function",
		Function: ToolCallFunction{Name: "some_other_tool", Arguments: `{"whatever":1}`},
	}}
	got, err := parseDeepToolCalls(calls)
	if err != nil {
		t.Fatalf("an unrelated tool call must not fail the read: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no candidates, got %d", len(got))
	}
}

// A model that finds nothing may simply not call the tool. That is a
// clean result, not a failure.
func TestParseDeepToolCalls_NoCallsIsClean(t *testing.T) {
	got, err := parseDeepToolCalls(nil)
	if err != nil {
		t.Fatalf("no tool calls must not error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("want no candidates, got %d", len(got))
	}
}
