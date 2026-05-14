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
		var got ChatRequest
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Errorf("decode body: %v", err)
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
