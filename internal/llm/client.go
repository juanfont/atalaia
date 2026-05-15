package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Message is one chat turn in an OpenAI-style request. ToolCalls is
// populated on response messages when the backend invokes a tool.
type Message struct {
	Role      string     `json:"role"`
	Content   string     `json:"content,omitempty"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Tool is an OpenAI tool definition; only "function" type is used here.
type Tool struct {
	Type     string       `json:"type"`
	Function ToolFunction `json:"function"`
}

type ToolFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters"`
}

// ToolCall is one tool invocation in a response. Arguments is a JSON
// string (the backend serializes the function call payload).
type ToolCall struct {
	ID       string           `json:"id"`
	Type     string           `json:"type"`
	Function ToolCallFunction `json:"function"`
}

type ToolCallFunction struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// ChatRequest is the trimmed shape Atalaia sends. Unset optional fields
// are omitted so the backend applies its own defaults.
type ChatRequest struct {
	Model          string         `json:"model"`
	Messages       []Message      `json:"messages"`
	MaxTokens      int            `json:"max_tokens,omitempty"`
	Temperature    float64        `json:"temperature,omitempty"`
	ResponseFormat map[string]any `json:"response_format,omitempty"`
	Tools          []Tool         `json:"tools,omitempty"`
	ToolChoice     any            `json:"tool_choice,omitempty"`
}

// ChatResponse captures only the fields we read. The full OpenAI
// response is much richer; ignoring unknown fields keeps us
// forward-compatible with backend variants.
type ChatResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
}

// ChatCompleter is the seam between Adjudicate and the HTTP transport.
// Tests substitute a fake.
type ChatCompleter interface {
	Complete(ctx context.Context, req ChatRequest) (ChatResponse, error)
	Probe(ctx context.Context) error
}

// Client is the production HTTP implementation of ChatCompleter,
// targeting any OpenAI chat-completions-compatible endpoint.
type Client struct {
	endpoint string
	model    string
	http     *http.Client
}

func NewClient(endpoint, model string, timeout time.Duration) *Client {
	endpoint = strings.TrimRight(endpoint, "/")
	return &Client{
		endpoint: endpoint,
		model:    model,
		http: &http.Client{
			Timeout: 0, // ctx carries the timeout
		},
	}
}

func (c *Client) Complete(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if req.Model == "" {
		req.Model = c.model
	}

	body, err := json.Marshal(req)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return ChatResponse{}, fmt.Errorf("llm status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return ChatResponse{}, fmt.Errorf("decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return ChatResponse{}, errors.New("llm returned no choices")
	}
	return out, nil
}

// Probe sends a single-token chat completion. It is used by
// `/healthz` and `atalaia probe` to confirm the endpoint is alive
// without committing significant inference budget.
func (c *Client) Probe(ctx context.Context) error {
	_, err := c.Complete(ctx, ChatRequest{
		Model:     c.model,
		Messages:  []Message{{Role: "user", Content: "ping"}},
		MaxTokens: 1,
	})
	return err
}
