package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_CompleteHappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("path=%q, want .../chat/completions", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type=%q", r.Header.Get("Content-Type"))
		}
		// A float field would decode a missing temperature as zero and
		// hide the omission that let the backend sample at its default.
		var got struct {
			Model       string   `json:"model"`
			Temperature *float64 `json:"temperature"`
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
		}
		if got.Temperature == nil || *got.Temperature != 0 {
			t.Errorf("temperature must be explicitly sent as zero, got %v", got.Temperature)
		}
		if got.Model != "test-model" {
			t.Errorf("Model=%q", got.Model)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{"message": map[string]any{"role": "assistant", "content": "ok"}},
			},
		})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "test-model", time.Second)
	resp, err := c.Complete(context.Background(), ChatRequest{
		Messages: []Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if resp.Choices[0].Message.Content != "ok" {
		t.Errorf("content=%q", resp.Choices[0].Message.Content)
	}
}

func TestClient_NonOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusBadRequest)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "m", time.Second)
	_, err := c.Complete(context.Background(), ChatRequest{Messages: []Message{{Role: "user", Content: "x"}}})
	if err == nil {
		t.Fatal("expected error on non-2xx")
	}
}

func TestClient_Probe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChatRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.MaxTokens != 1 {
			t.Errorf("Probe MaxTokens=%d, want 1", req.MaxTokens)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{{"message": map[string]any{"content": "."}}},
		})
	}))
	defer srv.Close()
	c := NewClient(srv.URL, "m", time.Second)
	if err := c.Probe(context.Background()); err != nil {
		t.Errorf("Probe: %v", err)
	}
}

func TestClient_RetainsCompletionDiagnostics(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req.ChatTemplateKwargs["enable_thinking"] != true {
			t.Error("thinking override lost")
		}
		_, _ = w.Write([]byte(`{"choices":[{"finish_reason":"length","message":{"role":"assistant","content":"partial","reasoning":"synthetic thought"}}],"usage":{"prompt_tokens":100,"completion_tokens":200,"total_tokens":300,"completion_tokens_details":{"reasoning_tokens":150}}}`))
	}))
	defer srv.Close()
	resp, err := NewClient(srv.URL, "m", time.Second).Complete(context.Background(), ChatRequest{ChatTemplateKwargs: map[string]any{"enable_thinking": true}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Choices[0].FinishReason != "length" || resp.Usage.TotalTokens != 300 || resp.Usage.CompletionTokensDetails.ReasoningTokens != 150 || resp.Choices[0].Message.Reasoning == "" {
		t.Fatalf("lost completion diagnostics: %+v", resp)
	}
}

func TestClient_ErrorDoesNotEchoBackendBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "sensitiveModelInput88", 500) }))
	defer srv.Close()
	_, err := NewClient(srv.URL, "m", time.Second).Complete(context.Background(), ChatRequest{})
	if err == nil || strings.Contains(err.Error(), "sensitiveModelInput88") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestClient_DecodeErrorDoesNotEchoResponseValue(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":918273645546372819}}]}`))
	}))
	defer srv.Close()
	_, err := NewClient(srv.URL, "m", time.Second).Complete(context.Background(), ChatRequest{})
	if err == nil || err.Error() != "decode: invalid llm response" {
		t.Fatalf("unsafe decode error: %v", err)
	}
}
