package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/juanfont/atalaia/internal/metrics"
	"github.com/juanfont/atalaia/internal/types"
)

// DeepResult is what one deep read produced. Truncated means coverage
// stopped at max_windows with added lines still unscanned, so an empty
// Candidates must not be read as a clean diff.
type DeepResult struct {
	Candidates []DeepCandidate
	Calls      int
	Windows    int
	Truncated  bool
	Latency    time.Duration
}

// DeepReader runs the opt-in second pass: it reads a diff's added lines
// with no detector findings in the prompt and returns candidate
// credentials. It does not decide where they are. Ground does that,
// against the diff.
type DeepReader struct {
	cfg    types.LLMConfig
	client ChatCompleter
	prompt *PromptTemplate
	sem    *Semaphore
}

// NewDeepReader loads the deep templates and returns a reader. The
// semaphore is shared with the Adjudicator: both stages contend for the
// same backend, and at max_inflight 1 they take turns rather than
// opening a second queue against one GPU.
func NewDeepReader(cfg types.LLMConfig, client ChatCompleter, sem *Semaphore) (*DeepReader, error) {
	prompt, err := LoadDeepPromptTemplate(cfg)
	if err != nil {
		return nil, err
	}
	return &DeepReader{cfg: cfg, client: client, prompt: prompt, sem: sem}, nil
}

// PromptFingerprint is the deep prompt's "profile:hash", surfaced on
// /version so a stale on-disk template is visible.
func (r *DeepReader) PromptFingerprint() string { return r.prompt.Fingerprint() }

// Scan reads the diff's added lines in budget-sized windows.
//
// findings is the detector finding count for this request, used only by
// deep_scan.require_findings. Windows are scanned sequentially under a
// single semaphore acquisition, mirroring how Adjudicate handles
// batches: one request holds one slot, however many calls it makes.
func (r *DeepReader) Scan(ctx context.Context, diff []byte, findings int) (DeepResult, error) {
	if r.cfg.DeepScan.RequireFindings && findings == 0 {
		return DeepResult{}, nil
	}

	cb := r.cfg.ContextBudget
	// The deep read gets its own, smaller window than adjudication.
	// Falls back to the shared context budget when unset.
	windowTokens := r.cfg.DeepScan.WindowTokens
	if windowTokens <= 0 {
		windowTokens = cb.InputTokens - cb.OutputTokens
	}
	windows, truncated := buildDeepWindows(diff, windowTokens, r.cfg.DeepScan.MaxWindows)
	if len(windows) == 0 {
		return DeepResult{}, nil
	}

	if err := r.sem.Acquire(ctx); err != nil {
		return DeepResult{}, err
	}
	defer r.sem.Release()

	start := time.Now()
	out := DeepResult{Windows: len(windows), Truncated: truncated}

	for i, w := range windows {
		cands, err := r.scanWindow(ctx, w, i, len(windows))
		out.Calls++
		if err != nil {
			return DeepResult{}, err
		}
		out.Candidates = append(out.Candidates, cands...)
	}

	out.Latency = time.Since(start)
	metrics.DeepWindows.Observe(float64(out.Windows))
	metrics.DeepLatencySeconds.Observe(out.Latency.Seconds())
	return out, nil
}

// scanWindow is one LLM call. Split out so the per-call timeout's
// cancel runs when the call finishes, not when the whole scan does.
func (r *DeepReader) scanWindow(ctx context.Context, window string, i, total int) ([]DeepCandidate, error) {
	callCtx := ctx
	if r.cfg.RequestTimeout > 0 {
		var cancel func()
		callCtx, cancel = context.WithTimeout(ctx, r.cfg.RequestTimeout)
		defer cancel()
	}

	system, user, err := r.prompt.RenderDeep(DeepPromptData{Window: window})
	if err != nil {
		return nil, fmt.Errorf("render deep window %d/%d: %w", i+1, total, err)
	}

	req := ChatRequest{
		Model: r.cfg.Model,
		Messages: []Message{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		MaxTokens:   r.cfg.ContextBudget.OutputTokens,
		Temperature: 0,
		// ResponseFormat omitted for the same reason as adjudication:
		// vLLM's xgrammar wedges on some small-model combinations. The
		// tool path below is the principled fix where supported.
	}
	if r.cfg.UseTools {
		req.Tools = []Tool{DeepTool()}
		req.ToolChoice = map[string]any{
			"type":     "function",
			"function": map[string]any{"name": DeepToolName},
		}
	}

	resp, err := r.client.Complete(callCtx, req)
	if err != nil {
		return nil, fmt.Errorf("deep call %d/%d: %w", i+1, total, err)
	}
	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("deep call %d/%d: response carried no choices", i+1, total)
	}

	msg := resp.Choices[0].Message
	var cands []DeepCandidate
	switch {
	case r.cfg.UseTools && len(msg.ToolCalls) > 0:
		cands, err = parseDeepToolCalls(msg.ToolCalls)
	default:
		cands, err = parseDeepResponse(msg.Content)
	}
	if err != nil {
		preview := msg.Content
		if len(preview) > 400 {
			preview = preview[:400] + "..."
		}
		return nil, fmt.Errorf("parse deep response %d/%d (%d chars, %d tool_calls): %w; head=%q",
			i+1, total, len(msg.Content), len(msg.ToolCalls), err, preview)
	}

	if max := r.cfg.DeepScan.MaxCandidates; max > 0 && len(cands) > max {
		cands = cands[:max]
	}
	return cands, nil
}
