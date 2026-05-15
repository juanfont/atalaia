package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/metrics"
	"github.com/juanfont/atalaia/internal/types"
)

// Adjudicator owns the LLM client, the prompt template, the queue
// semaphore, and the short-circuit policy. One instance per process.
type Adjudicator struct {
	cfg      types.LLMConfig
	client   ChatCompleter
	prompt   *PromptTemplate
	sem      *Semaphore
	maxCount int
}

// NewAdjudicator constructs an Adjudicator from config. The prompt
// template files referenced by cfg.Profiles[cfg.Profile] must be
// readable at startup or this returns an error.
func NewAdjudicator(cfg types.LLMConfig, client ChatCompleter) (*Adjudicator, error) {
	if client == nil {
		return nil, fmt.Errorf("llm: nil client")
	}
	tmpl, err := LoadPromptTemplate(cfg)
	if err != nil {
		return nil, err
	}
	return &Adjudicator{
		cfg:      cfg,
		client:   client,
		prompt:   tmpl,
		sem:      NewSemaphore(cfg.MaxInflight, cfg.QueueMax),
		maxCount: cfg.MaxFindingsPerRequest,
	}, nil
}

// QueueDepth and Inflight expose the semaphore state for the metrics
// layer (milestone 6).
func (a *Adjudicator) QueueDepth() int64 { return a.sem.QueueDepth() }
func (a *Adjudicator) Inflight() int     { return a.sem.Inflight() }

// Probe is a thin pass-through to the underlying client. Used by
// /healthz and `atalaia probe`.
func (a *Adjudicator) Probe(ctx context.Context) error { return a.client.Probe(ctx) }

// AdjudicateResult is the bundle Adjudicate returns. Truncated is true
// when MaxFindingsPerRequest capped the input.
type AdjudicateResult struct {
	Result
	Truncated bool
}

// Adjudicate decides verdicts for every dedup'd finding. Verified and
// sentinel findings are short-circuited; the rest go to the LLM.
//
// Mode selection:
//   - if the diff plus all findings fit the input budget, one LLM call
//     with the whole diff (richer cross-file context).
//   - otherwise per-finding mode: each finding gets ±FindingContextLines
//     of surrounding new-file code, findings are packed into batches
//     that fit the budget, batches go through sequential LLM calls
//     under a single semaphore slot.
//
// The semaphore gates the LLM stage only — short-circuit requests
// never block on it.
func (a *Adjudicator) Adjudicate(ctx context.Context, diff []byte, deduped []detector.DedupedFinding) (AdjudicateResult, error) {
	truncated := false
	if a.maxCount > 0 && len(deduped) > a.maxCount {
		deduped = deduped[:a.maxCount]
		truncated = true
	}

	verdicts := make([]Verdict, 0, len(deduped))
	var llmBound []detector.DedupedFinding
	for _, d := range deduped {
		if v, ok := shortCircuit(d); ok {
			verdicts = append(verdicts, v)
			continue
		}
		llmBound = append(llmBound, d)
	}

	if len(llmBound) == 0 {
		return AdjudicateResult{
			Result:    Result{Verdicts: verdicts, LLMInvoked: false},
			Truncated: truncated,
		}, nil
	}

	if err := a.sem.Acquire(ctx); err != nil {
		return AdjudicateResult{}, err
	}
	defer a.sem.Release()

	cb := a.cfg.ContextBudget
	var batches []PromptData
	if fitsSingleCall(diff, llmBound, cb.InputTokens, cb.OutputTokens) {
		batches = []PromptData{{
			Diff:     string(diff),
			Findings: findingsFromDeduped(llmBound),
		}}
	} else {
		idx := buildFileIndex(diff)
		packed := packBatches(llmBound, idx, cb.FindingContextLines, cb.InputTokens, cb.OutputTokens)
		batches = make([]PromptData, len(packed))
		for i, b := range packed {
			batches[i] = PromptData{Findings: b}
		}
	}

	var (
		llmVerdicts  []Verdict
		totalLatency time.Duration
	)
	for i, batch := range batches {
		callCtx := ctx
		if a.cfg.RequestTimeout > 0 {
			var cancel func()
			callCtx, cancel = context.WithTimeout(ctx, a.cfg.RequestTimeout)
			defer cancel()
		}

		system, user, err := a.prompt.Render(batch)
		if err != nil {
			return AdjudicateResult{}, fmt.Errorf("render batch %d/%d: %w", i+1, len(batches), err)
		}

		req := ChatRequest{
			Model: a.cfg.Model,
			Messages: []Message{
				{Role: "system", Content: system},
				{Role: "user", Content: user},
			},
			MaxTokens:   cb.OutputTokens,
			Temperature: 0,
			// ResponseFormat omitted: vLLM's xgrammar wedges on some
			// small-model + nested-required-fields combinations (see
			// internal-docs/vllm-host.md). The use-tools path (below)
			// is the principled fix for backends that support it.
		}
		if a.cfg.UseTools {
			req.Tools = []Tool{VerdictTool()}
			req.ToolChoice = map[string]any{
				"type":     "function",
				"function": map[string]any{"name": VerdictToolName},
			}
		}

		start := time.Now()
		resp, err := a.client.Complete(callCtx, req)
		totalLatency += time.Since(start)
		if err != nil {
			return AdjudicateResult{}, fmt.Errorf("llm call batch %d/%d: %w", i+1, len(batches), err)
		}

		msg := resp.Choices[0].Message
		var parsed []Verdict
		switch {
		case a.cfg.UseTools && len(msg.ToolCalls) > 0:
			parsed, err = parseToolCallVerdicts(msg.ToolCalls)
		default:
			parsed, err = parseVerdictResponse(msg.Content)
		}
		if err != nil {
			preview := msg.Content
			if len(preview) > 400 {
				preview = preview[:400] + "..."
			}
			return AdjudicateResult{}, fmt.Errorf("parse llm response batch %d/%d (%d chars, %d tool_calls): %w; head=%q",
				i+1, len(batches), len(msg.Content), len(msg.ToolCalls), err, preview)
		}
		llmVerdicts = append(llmVerdicts, parsed...)
	}

	verdicts = append(verdicts, mergeAndFill(llmBound, llmVerdicts)...)
	return AdjudicateResult{
		Result: Result{
			Verdicts:   verdicts,
			LLMInvoked: true,
			LLMCalls:   len(batches),
			LLMLatency: totalLatency,
		},
		Truncated: truncated,
	}, nil
}

// rawVerdict mirrors a single verdict object as it appears on the
// wire. parseVerdictResponse normalizes whatever shape the model
// produced into a []Verdict.
type rawVerdict struct {
	FindingID  string  `json:"finding_id"`
	Verdict    string  `json:"verdict"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// parseToolCallVerdicts pulls verdicts out of the OpenAI tool_calls
// response shape. The model invokes VerdictToolName with the
// VerdictSchema-shaped arguments as a JSON string; we delegate the
// actual decode to parseVerdictResponse so envelope vs bare-array
// handling stays in one place.
func parseToolCallVerdicts(calls []ToolCall) ([]Verdict, error) {
	if len(calls) == 0 {
		return nil, fmt.Errorf("no tool_calls in response")
	}
	for _, c := range calls {
		if c.Function.Name != VerdictToolName {
			continue
		}
		return parseVerdictResponse(c.Function.Arguments)
	}
	return nil, fmt.Errorf("no %q tool_call in response", VerdictToolName)
}

// parseVerdictResponse decodes the JSON the model produced. It tolerates:
//   - leading / trailing whitespace
//   - a ```json ... ``` fenced code block
//   - the envelope shape {"verdicts":[...]}
//   - a bare top-level array [...] (some models skip the envelope when
//     guided decoding is off)
func parseVerdictResponse(raw string) ([]Verdict, error) {
	body := strings.TrimSpace(raw)
	if strings.HasPrefix(body, "```") {
		if i := strings.IndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), "```")
		body = strings.TrimSpace(body)
	}

	var verdicts []rawVerdict
	switch {
	case strings.HasPrefix(body, "["):
		if err := json.Unmarshal([]byte(body), &verdicts); err != nil {
			return nil, err
		}
	case strings.HasPrefix(body, "{"):
		var envelope struct {
			Verdicts []rawVerdict `json:"verdicts"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			return nil, err
		}
		verdicts = envelope.Verdicts
	default:
		return nil, fmt.Errorf("response is neither a JSON object nor array")
	}

	out := make([]Verdict, len(verdicts))
	for i, v := range verdicts {
		out[i] = Verdict{
			FindingID:  v.FindingID,
			Verdict:    v.Verdict,
			Confidence: v.Confidence,
			Reason:     v.Reason,
		}
	}
	return out, nil
}

// mergeAndFill correlates LLM-returned verdicts to llmBound findings by
// finding_id. Any missing IDs get the design's conservative fallback —
// confirmed at confidence 0 so a missed real secret stays loud, with a
// reason string that surfaces the issue in the audit log. Each gap-fill
// bumps atalaia_llm_missing_verdict_total so prompt/model drift is
// visible operationally.
func mergeAndFill(llmBound []detector.DedupedFinding, llmOut []Verdict) []Verdict {
	byID := make(map[string]Verdict, len(llmOut))
	for _, v := range llmOut {
		byID[v.FindingID] = v
	}

	out := make([]Verdict, 0, len(llmBound))
	for _, d := range llmBound {
		if v, ok := byID[d.ID]; ok {
			// Defensive: a backend without schema enforcement could
			// hand back an unknown verdict string. Treat that as a
			// gap rather than smuggling it through.
			if v.Verdict == VerdictConfirmed || v.Verdict == VerdictDismissed {
				out = append(out, v)
				continue
			}
		}
		metrics.LLMMissingVerdictTotal.Inc()
		out = append(out, Verdict{
			FindingID:  d.ID,
			Verdict:    VerdictConfirmed,
			Confidence: 0,
			Reason:     "model returned no verdict for this finding",
		})
	}
	return out
}
