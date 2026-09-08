package llm

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strings"
	"time"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/metrics"
	"github.com/juanfont/atalaia/internal/types"
)

// DeepStatus is how far a deep read got. The shallow verdicts are valid
// under every status; only Complete means the deep channel covered the
// whole diff.
type DeepStatus string

const (
	// DeepComplete: every planned window was scanned.
	DeepComplete DeepStatus = "complete"
	// DeepPartial: some windows were scanned, then the read stepped
	// aside for queued adjudication work. Discoveries from the scanned
	// windows are returned; the rest of the diff was not read.
	DeepPartial DeepStatus = "partial"
	// DeepDeferred: the backend was busy and no window was scanned. A
	// fast, explicit "not now", never a 503: the caller may re-request
	// deep later, or accept the shallow result.
	DeepDeferred DeepStatus = "deferred"
	// DeepSkipped: a selection rule (require_findings, max_added_lines,
	// sample_rate) excluded this diff. Reason names the rule.
	DeepSkipped DeepStatus = "skipped"
)

// DeepResult is what one deep read produced.
//
// Windows is the planned count, WindowsScanned how many actually ran.
// Truncated means the plan itself was cut at max_windows. Under any
// status but Complete, an empty Candidates must not be read as a clean
// diff.
type DeepResult struct {
	Status         DeepStatus
	Reason         string
	Candidates     []DeepCandidate
	Calls          int
	Windows        int
	WindowsScanned int
	Truncated      bool
	Latency        time.Duration
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
	// draw returns a uniform [0,1) sample for sample_rate. Injectable
	// so tests can pin the outcome.
	draw func() float64
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
	return &DeepReader{cfg: cfg, client: client, prompt: prompt, sem: sem, draw: rand.Float64}, nil
}

// PromptFingerprint is the deep prompt's "profile:hash", surfaced on
// /version so a stale on-disk template is visible.
func (r *DeepReader) PromptFingerprint() string { return r.prompt.Fingerprint() }

// Scan reads the diff's added lines in budget-sized windows.
//
// findings is the detector finding count for this request, used by
// deep_scan.require_findings.
//
// Admission is per window and never queues. Each window takes the LLM
// slot with TryAcquire: only if it is free, and never while an
// adjudication is waiting for it. Adjudication owns the queue; the deep
// read borrows idle capacity and steps aside on contention. So under
// load the deep read defers or comes back partial, and the shallow
// result still goes out as a 200. It cannot push an adjudication past
// queue_max, because a refused TryAcquire is not a waiter.
func (r *DeepReader) Scan(ctx context.Context, diff []byte, findings int) (DeepResult, error) {
	if r.cfg.DeepScan.RequireFindings && findings == 0 {
		return DeepResult{Status: DeepSkipped, Reason: "require_findings"}, nil
	}
	if max := r.cfg.DeepScan.MaxAddedLines; max > 0 {
		if n := countAddedLines(diff); n > max {
			return DeepResult{Status: DeepSkipped, Reason: "max_added_lines"}, nil
		}
	}
	if rate := r.cfg.DeepScan.SampleRate; rate > 0 && rate < 1 && r.draw() >= rate {
		return DeepResult{Status: DeepSkipped, Reason: "sample_rate"}, nil
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
		return DeepResult{Status: DeepComplete}, nil
	}

	start := time.Now()
	out := DeepResult{Windows: len(windows), Truncated: truncated}

	for i, w := range windows {
		if !r.sem.TryAcquire(ctx, r.cfg.DeepScan.AdmissionWait) {
			break
		}
		cands, err := r.scanWindow(ctx, w, i, len(windows))
		r.sem.Release()
		out.Calls++
		if err != nil {
			return DeepResult{}, err
		}
		out.WindowsScanned++
		out.Candidates = append(out.Candidates, cands...)
	}

	switch {
	case out.WindowsScanned == 0:
		out.Status = DeepDeferred
		out.Reason = "backend busy"
	case out.WindowsScanned < out.Windows:
		out.Status = DeepPartial
		out.Reason = "backend busy"
	default:
		out.Status = DeepComplete
	}

	out.Latency = time.Since(start)
	if out.WindowsScanned > 0 {
		metrics.DeepWindows.Observe(float64(out.WindowsScanned))
		metrics.DeepLatencySeconds.Observe(out.Latency.Seconds())
	}
	return out, nil
}

// countAddedLines is the size measure behind max_added_lines: added
// lines only, the same set the deep read scans.
func countAddedLines(diff []byte) int {
	n := 0
	for _, b := range detector.WalkDiff(diff) {
		n += strings.Count(b.Content, "\n") + 1
	}
	return n
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
