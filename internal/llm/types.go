package llm

import "time"

// Verdict is the per-finding decision produced by Adjudicate. The API
// layer converts these into the wire-shape api.Verdict (adding the
// file/line/match_preview/detections fields it owns).
type Verdict struct {
	FindingID  string
	Verdict    string // VerdictConfirmed | VerdictDismissed
	Confidence float64
	Reason     string
}

// Result is the bundle Adjudicate returns. Verdicts is in input order
// (the API layer merges by FindingID, so order is informational).
type Result struct {
	Verdicts   []Verdict
	LLMInvoked bool
	LLMCalls   int
	LLMLatency time.Duration
}
