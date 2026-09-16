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
	Reasoning        string     `json:"reasoning,omitempty"`
	ReasoningContent string     `json:"reasoning_content,omitempty"`
	Role             string     `json:"role"`
	Content          string     `json:"content,omitempty"`
	ToolCalls        []ToolCall `json:"tool_calls,omitempty"`
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
// are omitted so the backend applies its own defaults. Temperature is
// always sent: zero requests greedy decoding, not the backend default.
type ChatRequest struct {
	ChatTemplateKwargs map[string]any `json:"chat_template_kwargs,omitempty"`
	Model              string         `json:"model"`
	Messages           []Message      `json:"messages"`
	MaxTokens          int            `json:"max_tokens,omitempty"`
	Temperature        float64        `json:"temperature"`
	ResponseFormat     map[string]any `json:"response_format,omitempty"`
	Tools              []Tool         `json:"tools,omitempty"`
	ToolChoice         any            `json:"tool_choice,omitempty"`
}

// TokenUsage contains backend accounting, including reasoning tokens when exposed.
type TokenUsage struct {
	PromptTokens            int `json:"prompt_tokens"`
	CompletionTokens        int `json:"completion_tokens"`
	TotalTokens             int `json:"total_tokens"`
	CompletionTokensDetails struct {
		ReasoningTokens int `json:"reasoning_tokens"`
	} `json:"completion_tokens_details,omitempty"`
}

// ChatResponse captures only the fields we read. Unknown fields are ignored
// for compatibility with backend variants.
type ChatResponse struct {
	Usage   TokenUsage `json:"usage"`
	Choices []struct {
		Message      Message `json:"message"`
		FinishReason string  `json:"finish_reason"`
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
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return ChatResponse{}, fmt.Errorf("llm status %d", resp.StatusCode)
	}

	var out ChatResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		// Decoder type errors can include values from the backend response.
		return ChatResponse{}, errors.New("decode: invalid llm response")
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

// thinkingParameters leaves generic backends untouched unless the operator
// explicitly opts into a supported chat-template parameter.
func thinkingParameters(enabled *bool) map[string]any {
	if enabled == nil {
		return nil
	}
	return map[string]any{"enable_thinking": *enabled}
}
