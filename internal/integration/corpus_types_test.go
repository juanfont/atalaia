package integration

import "strings"

type expectation struct {
	Match   string `json:"match"`
	Verdict string `json:"verdict"`
}

type fixture struct {
	Tags          []string            `json:"tags,omitempty"`
	Pair          string              `json:"pair,omitempty"`
	ExpectSecrets []secretExpectation `json:"expect_secrets,omitempty"`
	MaxAlerts     *int                `json:"max_alerts,omitempty"`
	MaxUnreviewed *int                `json:"max_unreviewed,omitempty"`
	Description   string              `json:"description"`
	MinAfterDedup int                 `json:"min_after_dedup"`
	Expectations  []expectation       `json:"expectations"`
	// MaxConfirmed, when set, asserts stats.confirmed <= this on every
	// run. Used by large-finding-count fixtures to guard the batching
	// fix: without per-call batching the model drops the tail of a big
	// finding set, which gap-fills to "confirmed" and inflates this.
	MaxConfirmed *int `json:"max_confirmed,omitempty"`
	// Deep sends ?deep=1 and enables the discovery assertions below.
	Deep bool `json:"deep,omitempty"`
	// ExpectDiscoveries names values that must appear in discoveries[]:
	// secrets no detector flags, which only the deep read can surface.
	ExpectDiscoveries []discoveryExpectation `json:"expect_discoveries,omitempty"`
	// MaxDiscoveries caps discoveries[] length. Zero with Deep set
	// means "expect none": the false-alarm gate that decides whether
	// the channel is worth reading at all.
	MaxDiscoveries *int `json:"max_discoveries,omitempty"`
}

// discoveryExpectation names a secret the deep read must surface.
//
// Prefer file+line over match. The model chooses how much of the line
// to return (a bare password, or the whole URL it sits in), and
// URL-aware redaction reshapes the preview accordingly, so pinning the
// exact string asserts the model's phrasing rather than the behaviour
// that matters: did it find the secret, at the right place. Match stays
// supported for values whose preview shape is stable.
type discoveryExpectation struct {
	Match string `json:"match,omitempty"`
	Kind  string `json:"kind,omitempty"`
	File  string `json:"file,omitempty"`
	Line  int    `json:"line,omitempty"`
}

type verdict struct {
	ID           string  `json:"id"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	MatchPreview string  `json:"match_preview"`
	Verdict      string  `json:"verdict"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

type discovery struct {
	ID           string  `json:"id"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	MatchPreview string  `json:"match_preview"`
	Kind         string  `json:"kind"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

type checkResponse struct {
	RequestID   string      `json:"request_id"`
	Verdicts    []verdict   `json:"verdicts"`
	Discoveries []discovery `json:"discoveries"`
	Stats       struct {
		AfterDedup     int  `json:"after_dedup"`
		Confirmed      int  `json:"confirmed"`
		Dismissed      int  `json:"dismissed"`
		LLMInvoked     bool `json:"llm_invoked"`
		Unreviewed     int  `json:"unreviewed"`
		Truncated      bool `json:"truncated"`
		DetectorErrors []struct {
			Detector string `json:"detector"`
		} `json:"detector_errors"`
		DeepScan *struct {
			Status     string `json:"status"`
			Reason     string `json:"reason"`
			Ran        bool   `json:"ran"`
			Windows    int    `json:"windows"`
			Candidates int    `json:"candidates"`
			Discovered int    `json:"discovered"`
			Ungrounded int    `json:"ungrounded"`
			Truncated  bool   `json:"truncated"`
			Error      string `json:"error"`
		} `json:"deep_scan"`
	} `json:"stats"`
}

// secretExpectation accepts a confirmed detector verdict or a grounded
// discovery at this location. Value is source evidence for the offline
// fixture validator; responses redact it and may report a containing URL.
type secretExpectation struct {
	File  string `json:"file"`
	Line  int    `json:"line"`
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

func hasTag(fx fixture, tag string) bool {
	for _, got := range fx.Tags {
		if got == tag {
			return true
		}
	}
	return false
}

func foundSecret(resp *checkResponse, want secretExpectation) bool {
	for _, v := range resp.Verdicts {
		if v.Verdict == "confirmed" && !isUnreviewed(v) && v.File == want.File && v.Line == want.Line {
			return true
		}
	}
	for _, d := range resp.Discoveries {
		if d.File == want.File && d.Line == want.Line && d.Kind == want.Kind {
			return true
		}
	}
	return false
}

func isUnreviewed(v verdict) bool {
	return v.Verdict == "unreviewed" || (v.Confidence == 0 && strings.HasPrefix(v.Reason, "model returned no verdict"))
}

func alertCount(resp *checkResponse) int {
	n := len(resp.Discoveries)
	for _, v := range resp.Verdicts {
		if v.Verdict == "confirmed" {
			n++
		}
	}
	return n
}

// completeCoverage keeps a successful-looking partial response from
// counting as a clean evaluation sample.
func completeCoverage(resp *checkResponse) bool {
	ds := resp.Stats.DeepScan
	return !resp.Stats.Truncated && len(resp.Stats.DetectorErrors) == 0 && ds != nil && ds.Ran && ds.Status == "complete" && !ds.Truncated && ds.Error == ""
}
