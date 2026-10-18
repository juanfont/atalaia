package llm

import (
	"context"
	"time"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/redact"
)

// ReviewDetectorType labels a grounded deep discovery when it is handed
// to the adjudicator, in the place a detector name would go.
const ReviewDetectorType = "deep_read"

// ReviewResult is what reviewing a set of grounded discoveries produced.
//
// Admitted is false when no LLM slot came free within the wait. Nothing
// was reviewed then, and Kept is empty. Withheld counts discoveries the
// model returned no verdict for: unconfirmed, so not reported.
type ReviewResult struct {
	Admitted  bool
	Kept      []Discovery
	Dismissed int
	Withheld  int
	Calls     int
	Latency   time.Duration
}

// Review puts grounded deep discoveries through adjudication: the same
// default-dismiss prompt, context and verdict schema detector findings
// get. The deep read proposes with a recall posture; this is the
// precision step it lacked. Only confirmed discoveries are kept, and
// they carry the adjudicator's confidence and reason.
//
// Admission works like the deep read's: it borrows an idle slot with
// TryAcquire and never queues behind adjudication.
func (a *Adjudicator) Review(ctx context.Context, diff []byte, discoveries []Discovery, wait time.Duration) (ReviewResult, error) {
	if len(discoveries) == 0 {
		return ReviewResult{Admitted: true}, nil
	}
	if !a.sem.TryAcquire(ctx, wait) {
		return ReviewResult{}, nil
	}
	defer a.sem.Release()

	findings := make([]detector.DedupedFinding, len(discoveries))
	for i, d := range discoveries {
		findings[i] = detector.DedupedFinding{
			ID:    d.ID,
			File:  d.File,
			Line:  d.Line,
			Match: d.Match,
			Detections: []detector.Detection{{
				DetectorType: ReviewDetectorType,
				DetectorName: ReviewDetectorType,
				Rule:         d.Kind,
			}},
		}
	}
	res, err := a.adjudicateHeld(ctx, diff, findings)
	out := ReviewResult{Admitted: true, Calls: res.LLMCalls, Latency: res.LLMLatency}
	if err != nil {
		return out, err
	}

	byID := make(map[string]Verdict, len(res.Verdicts))
	for _, v := range res.Verdicts {
		byID[v.FindingID] = v
	}
	for _, d := range discoveries {
		switch v := byID[d.ID]; v.Verdict {
		case VerdictConfirmed:
			d.Confidence = v.Confidence
			d.Reason = redact.Scrub(v.Reason, d.Match)
			out.Kept = append(out.Kept, d)
		case VerdictDismissed:
			out.Dismissed++
		default:
			out.Withheld++
		}
	}
	return out, nil
}
