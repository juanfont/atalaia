package llm

import (
	"encoding/json"
	"testing"
)

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

// The backend's arguments field is itself JSON inside the HTTP JSON envelope.
// Decode each transport layer once, preserving source escapes in the candidate.
// A model that evaluates the source literal must fail exact grounding.
func TestDeepEscapesThroughResponseAndGrounding(t *testing.T) {
	for _, tc := range []struct {
		name      string
		source    string
		jsonValue string
		want      string
		grounded  bool
	}{
		{"literal Unicode escape", `Aspen\u003fBrook72`, `"Aspen\\u003fBrook72"`, `Aspen\u003fBrook72`, true},
		{"two source backslashes", `Cedar\\Trail85`, `"Cedar\\\\Trail85"`, `Cedar\\Trail85`, true},
		{"decoded Unicode rejected", `Aspen\u003fBrook72`, `"Aspen\u003fBrook72"`, `Aspen?Brook72`, false},
		{"collapsed backslash rejected", `Cedar\\Trail85`, `"Cedar\\Trail85"`, `Cedar\Trail85`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			arguments := `{"candidates":[{"value":` + tc.jsonValue + `,"kind":"credential","confidence":1,"reason":"Configuration password"}]}`
			for _, tool := range []bool{false, true} {
				msg := Message{Role: "assistant", Content: arguments}
				if tool {
					msg.Content = ""
					msg.ToolCalls = []ToolCall{{Type: "function", Function: ToolCallFunction{Name: DeepToolName, Arguments: arguments}}}
				}
				wire, err := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": msg}}})
				if err != nil {
					t.Fatal(err)
				}
				var response ChatResponse
				if err := json.Unmarshal(wire, &response); err != nil {
					t.Fatal(err)
				}
				received := response.Choices[0].Message
				var candidates []DeepCandidate
				if tool {
					candidates, err = parseDeepToolCalls(received.ToolCalls)
				} else {
					candidates, err = parseDeepResponse(received.Content)
				}
				if err != nil {
					t.Fatal(err)
				}
				if len(candidates) != 1 || candidates[0].Value != tc.want {
					t.Fatalf("tool=%v: candidates = %#v, want exact value %q", tool, candidates, tc.want)
				}
				diff := []byte("diff --git a/config.json b/config.json\n--- /dev/null\n+++ b/config.json\n@@ -0,0 +1 @@\n+{\"password\":\"" + tc.source + "\"}\n")
				discoveries, _ := Ground(diff, candidates, nil)
				if (len(discoveries) == 1) != tc.grounded {
					t.Fatalf("tool=%v: grounded=%d, want grounded=%v", tool, len(discoveries), tc.grounded)
				}
				if tc.grounded && discoveries[0].Match != tc.source {
					t.Fatal("grounding changed source bytes")
				}
			}
		})
	}
}
