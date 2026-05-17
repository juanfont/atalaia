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

// Stats is the per-request summary surfaced alongside the verdicts.
// Counts and timings are caller-facing observability; raw matches
// never appear here.
type Stats struct {
	DetectorsRun   []string `json:"detectors_run"`
	RawFindings    int      `json:"raw_findings"`
	AfterDedup     int      `json:"after_dedup"`
	Confirmed      int      `json:"confirmed"`
	Dismissed      int      `json:"dismissed"`
	LLMInvoked     bool     `json:"llm_invoked"`
	LLMCalls       int      `json:"llm_calls"`
	LLMModel       string   `json:"llm_model"`
	LLMLatencyMs   int64    `json:"llm_latency_ms"`
	TotalLatencyMs int64    `json:"total_latency_ms"`
	Truncated      bool     `json:"truncated"`
}

// CheckRequest is the application/json body shape for POST /check.
// Atalaia also accepts the raw unified diff as text/x-diff (or
// text/plain / application/x-patch), in which case this struct is
// not used.
type CheckRequest struct {
	Diff string `json:"diff"`
}

// CheckResponse is the POST /check 200 body.
type CheckResponse struct {
	RequestID string    `json:"request_id"`
	Verdicts  []Verdict `json:"verdicts"`
	Stats     Stats     `json:"stats"`
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
	Atalaia    string `json:"atalaia"`
	LLMModel   string `json:"llm_model"`
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
)
