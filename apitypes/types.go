package apitypes

// Verdict is one decision per deduplicated finding.
type Verdict struct {
	ID           string      `json:"id"`
	File         string      `json:"file"`
	Line         int         `json:"line"`
	MatchPreview string      `json:"match_preview"`
	Verdict      string      `json:"verdict"`
	Confidence   float64     `json:"confidence"`
	Reason       string      `json:"reason"`
	Detections   []Detection `json:"detections"`
}

// Detection is the audit trail of which raw detectors fired for one
// dedup'd finding. A single Verdict can carry multiple Detections.
type Detection struct {
	DetectorType string `json:"detector_type"`
	DetectorName string `json:"detector_name"`
	Rule         string `json:"rule"`
	Verified     bool   `json:"verified"`
}

// Discovery is a credential the LLM found in a diff that no detector
// flagged. It is a LOWER-TRUST channel than Verdict: nothing
// corroborates it but the model's judgement, checked only against the
// requirement that the value actually appears in the submitted diff.
// Do not gate a merge on a discovery without review.
//
// There is no verdict field: membership in the array is the claim.
// There is no detections field: nothing detected it.
type Discovery struct {
	ID           string  `json:"id"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	MatchPreview string  `json:"match_preview"`
	Kind         string  `json:"kind"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

// Discovery kinds.
const (
	KindCredential = "credential"
	KindPrivateKey = "private_key"
)

// DeepScanStats reports what the deep read did. Ran is false when the
// caller did not ask for it or the operator disabled it. Error is set
// when the deep read failed: the request still succeeded, but coverage
// is incomplete and an empty Discoveries must NOT be read as clean.
type DeepScanStats struct {
	Ran        bool   `json:"ran"`
	Calls      int    `json:"calls"`
	Windows    int    `json:"windows"`
	Candidates int    `json:"candidates"`
	Discovered int    `json:"discovered"`
	Ungrounded int    `json:"ungrounded"`
	Truncated  bool   `json:"truncated"`
	LatencyMs  int64  `json:"latency_ms"`
	Error      string `json:"error,omitempty"`
}

// Stats is the per-request summary surfaced alongside the verdicts.
// Counts and timings are caller-facing observability; raw matches
// never appear here.
type Stats struct {
	DetectorsRun []string `json:"detectors_run"`
	RawFindings  int      `json:"raw_findings"`
	AfterDedup   int      `json:"after_dedup"`
	Confirmed    int      `json:"confirmed"`
	Dismissed    int      `json:"dismissed"`
	// Unreviewed counts findings the LLM returned no usable verdict for
	// (gap-filled). Non-zero means some findings were neither confirmed
	// nor dismissed — retry or review them; do not read as clean.
	Unreviewed     int    `json:"unreviewed"`
	LLMInvoked     bool   `json:"llm_invoked"`
	LLMCalls       int    `json:"llm_calls"`
	LLMModel       string `json:"llm_model"`
	LLMLatencyMs   int64  `json:"llm_latency_ms"`
	TotalLatencyMs int64  `json:"total_latency_ms"`
	Truncated      bool   `json:"truncated"`
	// DetectorErrors lists detectors that failed to complete this
	// scan (timeout, crash, kill). Present only when non-empty. A
	// caller that sees entries here must NOT treat a zero-finding
	// response as authoritative "clean" — one or more detectors did
	// not run. When every detector fails and nothing was found,
	// /check returns 503 instead of a 200 with empty verdicts.
	DetectorErrors []DetectorError `json:"detector_errors,omitempty"`
	// DeepScan is present only when the caller asked for a deep read.
	// A nil DeepScan means no deep read was requested, which is not the
	// same as a deep read that found nothing.
	DeepScan *DeepScanStats `json:"deep_scan,omitempty"`
}

// DetectorError reports a single detector that failed during a scan.
// The Error string is diagnostic only and never carries a raw match.
type DetectorError struct {
	Detector string `json:"detector"`
	Error    string `json:"error"`
}

// CheckRequest is the application/json body shape for POST /check.
// Atalaia also accepts the raw unified diff as text/x-diff (or
// text/plain / application/x-patch), in which case this struct is
// not used.
type CheckRequest struct {
	Diff string `json:"diff"`
	// Deep opts into the second LLM pass over the whole diff. Costs an
	// LLM call even when detectors found nothing, and takes up to
	// llm.deep_scan.max_windows sequential calls. For non-gating
	// callers: a webhook watcher, not a pre-commit hook. Callers using
	// the raw diff content types pass ?deep=1 instead.
	Deep bool `json:"deep"`
}

// CheckResponse is the POST /check 200 body.
type CheckResponse struct {
	RequestID string    `json:"request_id"`
	Verdicts  []Verdict `json:"verdicts"`
	// Discoveries is present only for deep requests. Disjoint from
	// Verdicts by construction: a secret both a detector and the model
	// find is reported once, in Verdicts.
	Discoveries []Discovery `json:"discoveries,omitempty"`
	Stats       Stats       `json:"stats"`
}

// HealthzResponse is the body for GET /healthz and GET /readyz.
// /healthz always returns 200 if the process is up. /readyz returns
// 200/503 based on LLM reachability.
type HealthzResponse struct {
	Status       string `json:"status"`
	LLMReachable bool   `json:"llm_reachable"`
}

// VersionResponse is the body for GET /version.
type VersionResponse struct {
	Atalaia  string `json:"atalaia"`
	LLMModel string `json:"llm_model"`
	// Prompt is the loaded prompt's "profile:hash" fingerprint. It
	// changes whenever the on-disk template changes, so an operator can
	// confirm the live prompt matches the release (a deploy that
	// updates the binary but not prompts/ shows a stale hash here).
	Prompt string `json:"prompt"`
	// PromptDeep is the deep-scan prompt's "profile:hash" fingerprint,
	// empty when deep scan is disabled. Without it a deploy that
	// updates the binary but not the deep templates is invisible.
	PromptDeep string `json:"prompt_deep,omitempty"`
	Gitleaks   string `json:"gitleaks"`
	Trufflehog string `json:"trufflehog"`
	Kingfisher string `json:"kingfisher"`
}

// ErrorResponse is the body returned on every non-2xx from /check.
type ErrorResponse struct {
	Error string `json:"error"`
}

// Verdict-string constants. The legal values of Verdict.Verdict in
// API responses.
const (
	VerdictConfirmed = "confirmed"
	VerdictDismissed = "dismissed"
	// VerdictUnreviewed is a finding the LLM did not return a usable
	// verdict for (model omitted it, or returned an unparseable/unknown
	// verdict). It is NEITHER confirmed nor dismissed: confidence is 0
	// and the reason explains the gap. Consumers must not treat it as a
	// confirmed credential (don't page on it) NOR as clean (don't drop
	// it) — retry the scan or route it to a human.
	VerdictUnreviewed = "unreviewed"
)
