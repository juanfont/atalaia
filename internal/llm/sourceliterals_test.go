package llm

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestSourceLiteralsPreserveBytesAndBounds(t *testing.T) {
	window := "=== file\\name.json\n" + `{"password":"Rock\\Road47","note":"Oak\u003bPier23","again":"Rock\\Road47","plain":"visible"}` + "\n" + `password='Tide\"Cove58'` + "\n" + `unclosed="No\\End` + "\n"
	got := sourceLiterals(window)
	want := []SourceLiteral{{"literal_1", `Rock\\Road47`}, {"literal_2", `Oak\u003bPier23`}, {"literal_3", `Tide\"Cove58`}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("catalog = %#v", got)
	}
	if got := sourceLiterals("\"a\\\xffb\""); len(got) != 0 {
		t.Fatal("catalog cannot JSON-encode invalid UTF-8 exactly")
	}
	large := strings.Repeat(`"`+strings.Repeat(`\`, maxSourceLiteralBytes+1)+`" `, 10)
	if got := sourceLiterals(large); len(got) != 0 {
		t.Fatal("oversized literal included")
	}
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString(`"` + strings.Repeat("x", i+1) + `\path" `)
	}
	got = sourceLiterals(b.String())
	encoded, _ := json.Marshal(got)
	if len(got) > maxSourceLiterals || len(encoded) > maxSourceCatalogBytes {
		t.Fatal("catalog exceeded bounds")
	}
	for _, entry := range got {
		if !strings.Contains(b.String(), entry.Value) {
			t.Fatal("invented source value")
		}
	}
}

func TestSourceIDsResolveWithoutWeakeningGround(t *testing.T) {
	sources := []SourceLiteral{{"literal_1", `Rock\\Road47`}}
	for _, tc := range []struct {
		name, body string
		valid      bool
	}{
		{"ID", `{"candidates":[{"source_id":"literal_1","kind":"credential"}]}`, true},
		{"matching value", `{"candidates":[{"source_id":"literal_1","value":"Rock\\\\Road47","kind":"credential"}]}`, true},
		{"conflict", `{"candidates":[{"source_id":"literal_1","value":"Rock\\Road47","kind":"credential"}]}`, false},
		{"unknown", `{"candidates":[{"source_id":"literal_2","kind":"credential"}]}`, false},
		{"empty ID", `{"candidates":[{"source_id":"","kind":"credential"}]}`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseDeepResponseWithSources(tc.body, sources)
			toolGot, toolErr := parseDeepToolCallsWithSources([]ToolCall{{Function: ToolCallFunction{Name: DeepToolName, Arguments: tc.body}}}, sources)
			if (toolErr == nil) != tc.valid || !reflect.DeepEqual(toolGot, got) {
				t.Fatalf("tool/content mismatch: tool=%#v content=%#v err=%v", toolGot, got, toolErr)
			}
			if (err == nil) != tc.valid {
				t.Fatalf("err=%v", err)
			}
			if !tc.valid {
				return
			}
			if len(got) != 1 || got[0].Value != sources[0].Value {
				t.Fatal("source bytes changed")
			}
			diff := []byte("diff --git a/config b/config\n--- /dev/null\n+++ b/config\n@@ -0,0 +1 @@\n+password='" + sources[0].Value + "'\n")
			discoveries, _ := Ground(diff, got, nil)
			if len(discoveries) != 1 || discoveries[0].Match != sources[0].Value {
				t.Fatal("source selection did not ground exactly")
			}
			discoveries, _ = Ground([]byte(""), got, nil)
			if len(discoveries) != 0 {
				t.Fatal("ID bypassed grounding")
			}
			got[0].Kind = KindTestData
			discoveries, _ = Ground(diff, got, nil)
			if len(discoveries) != 0 {
				t.Fatal("ID bypassed test_data dismissal")
			}
			if _, err := parseDeepResponse(tc.body); err == nil {
				t.Fatal("ID accepted without catalog")
			}
		})
	}
}

func TestSourceSchemaDoesNotMutateDefault(t *testing.T) {
	before, _ := json.Marshal(DeepSchema)
	tool := deepToolWithSources([]SourceLiteral{{"literal_1", `Some\Value`}})
	encoded, _ := json.Marshal(tool)
	if !strings.Contains(string(encoded), "source_id") {
		t.Fatal("source schema missing")
	}
	after, _ := json.Marshal(DeepSchema)
	if string(before) != string(after) {
		t.Fatal("shared schema mutated")
	}
	plain, _ := json.Marshal(deepToolWithSources(nil))
	if strings.Contains(string(plain), "source_id") {
		t.Fatal("default schema changed")
	}
}

func TestDeepSourceSelectionRecoveryAndBudget(t *testing.T) {
	window := "=== config.json\n" + `{"password":"Rock\\Road47"}` + "\n"
	for _, tc := range []struct {
		name    string
		enabled bool
		budget  int
		replies []string
		calls   int
		want    string
		catalog bool
	}{
		{"selected", true, 24000, []string{`{"candidates":[{"source_id":"literal_1","kind":"credential"}]}`}, 1, `Rock\\Road47`, true},
		{"invalid copy replacement", true, 24000, []string{`{"candidates":[{"value":"Rock\\Road47","kind":"credential"}]}`, `{"candidates":[{"source_id":"literal_1","kind":"credential"}]}`}, 2, `Rock\\Road47`, true},
		{"default unchanged", false, 24000, []string{`{"candidates":[{"value":"Rock\\Road47","kind":"credential"}]}`}, 1, `Rock\Road47`, false},
		{"budget fallback", true, 1, []string{`{"candidates":[{"value":"Rock\\Road47","kind":"credential"}]}`}, 1, `Rock\Road47`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := deepTestConfig(t, 8)
			cfg.DeepScan.SourceLiterals = tc.enabled
			cfg.ContextBudget.InputTokens = tc.budget
			client := &fakeDeepClient{replies: tc.replies}
			reader, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
			if err != nil {
				t.Fatal(err)
			}
			got, calls, err := reader.scanWindow(context.Background(), window, 0, 1)
			if err != nil || calls != tc.calls || len(got) != 1 || got[0].Value != tc.want {
				t.Fatalf("got=%#v calls=%d err=%v", got, calls, err)
			}
			user := client.requests[0].Messages[1].Content
			if strings.Contains(user, "Escaped source literal catalog") != tc.catalog {
				t.Fatal("wrong catalog presence")
			}
			if !strings.Contains(user, window) {
				t.Fatal("source window removed")
			}
		})
	}
}

func TestDeepSourceCatalogIsLocalToWindow(t *testing.T) {
	cfg := deepTestConfig(t, 8)
	cfg.DeepScan.SourceLiterals = true
	cfg.ContextBudget.InputTokens = 24000
	reply := `{"candidates":[{"source_id":"literal_1","kind":"credential"}]}`
	client := &fakeDeepClient{replies: []string{reply, reply}}
	reader, err := NewDeepReader(cfg, client, NewSemaphore(1, 16))
	if err != nil {
		t.Fatal(err)
	}
	values := []string{`Rock\\Road47`, `Birch\\Harbor29`}
	for i, value := range values {
		got, _, err := reader.scanWindow(context.Background(), "=== config\npassword=\""+value+"\"\n", i, 2)
		if err != nil || len(got) != 1 || got[0].Value != value {
			t.Fatalf("window %d: %#v err=%v", i, got, err)
		}
	}
	if strings.Contains(client.requests[1].Messages[1].Content, values[0]) {
		t.Fatal("previous window source leaked into next request")
	}
}
