package api

// Verdict is one decision per deduplicated finding. Until the LLM
// filter lands in milestone 4, every non-short-circuited finding
// comes back as "pending_llm" with zero confidence.
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

type CheckRequest struct {
	Diff string `json:"diff"`
}

type CheckResponse struct {
	RequestID string    `json:"request_id"`
	Verdicts  []Verdict `json:"verdicts"`
	Stats     Stats     `json:"stats"`
}

type HealthzResponse struct {
	Status       string `json:"status"`
	LLMReachable bool   `json:"llm_reachable"`
}

type VersionResponse struct {
	Atalaia    string `json:"atalaia"`
	LLMModel   string `json:"llm_model"`
	Gitleaks   string `json:"gitleaks"`
	Trufflehog string `json:"trufflehog"`
	Kingfisher string `json:"kingfisher"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

// Verdict-string constants. "pending_llm" is the milestone-3 placeholder
// returned for findings that have not yet been adjudicated by the LLM.
const (
	VerdictConfirmed  = "confirmed"
	VerdictDismissed  = "dismissed"
	VerdictPendingLLM = "pending_llm"
)
