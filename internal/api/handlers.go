package api

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/atalaia/apitypes"
	"github.com/juanfont/atalaia/internal/audit"
	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/llm"
	"github.com/juanfont/atalaia/internal/metrics"
	"github.com/juanfont/atalaia/internal/redact"
	"github.com/oklog/ulid/v2"
)

func (a *App) Check(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := requestID(r)
	w.Header().Set("X-Request-ID", reqID)

	diff, err := readDiff(r, a.config.Server.MaxBodyBytes)
	if err != nil {
		metrics.CheckRequestsTotal.WithLabelValues("400").Inc()
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// ---- detect stage ----
	// The request context (not an artificial stage deadline) bounds how
	// long detectors may queue; the per-scan timeout lives inside Run
	// and starts only once a detector holds its slot. See detector.Run.
	detectStart := time.Now()
	raw, errs := detector.Run(r.Context(), diff, a.detectors, a.detectSem, a.config.Detectors.ParallelTimeout)
	metrics.CheckDurationSeconds.WithLabelValues("detect").Observe(time.Since(detectStart).Seconds())

	for name, err := range errs {
		a.logger.Warn().Str("detector", name).Str("request_id", reqID).Err(err).Msg("detector returned error")
		metrics.DetectorErrorsTotal.WithLabelValues(name).Inc()
	}
	for _, f := range raw {
		metrics.DetectorFindingsTotal.WithLabelValues(f.DetectorType).Inc()
	}

	// A detector failed and we have nothing to show. Returning 200 with
	// empty verdicts here would report a false "clean" — the caller
	// cannot tell a real clean from a scan that never ran. Fail closed
	// with a retryable 503 instead.
	if len(errs) > 0 && len(raw) == 0 {
		summary := detectorErrorSummary(errs)
		a.logger.Warn().Str("request_id", reqID).Str("detectors", summary).Msg("scan inconclusive, returning 503")
		metrics.CheckRequestsTotal.WithLabelValues("503").Inc()
		writeError(w, http.StatusServiceUnavailable, "scan inconclusive: "+summary)
		return
	}

	deduped := detector.Dedup(raw)

	// ---- LLM stage ----
	result, err := a.adjudicator.Adjudicate(r.Context(), diff, deduped)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, llm.ErrQueueFull) {
			status = http.StatusServiceUnavailable
		}
		a.logger.Error().Str("request_id", reqID).Err(err).Msg("adjudicate failed")
		metrics.CheckRequestsTotal.WithLabelValues(strconv.Itoa(status)).Inc()
		writeError(w, status, err.Error())
		return
	}
	if result.LLMInvoked {
		metrics.CheckDurationSeconds.WithLabelValues("llm").Observe(result.LLMLatency.Seconds())
	}

	verdicts := mergeVerdicts(deduped, result.Verdicts)
	confirmed, dismissed := countVerdicts(verdicts)
	metrics.VerdictsTotal.WithLabelValues(apitypes.VerdictConfirmed).Add(float64(confirmed))
	metrics.VerdictsTotal.WithLabelValues(apitypes.VerdictDismissed).Add(float64(dismissed))

	total := time.Since(start)
	resp := apitypes.CheckResponse{
		RequestID: reqID,
		Verdicts:  verdicts,
		Stats: apitypes.Stats{
			DetectorsRun:   detectorNames(a.detectors),
			RawFindings:    len(raw),
			AfterDedup:     len(deduped),
			Confirmed:      confirmed,
			Dismissed:      dismissed,
			LLMInvoked:     result.LLMInvoked,
			LLMCalls:       result.LLMCalls,
			LLMModel:       a.config.LLM.Model,
			LLMLatencyMs:   result.LLMLatency.Milliseconds(),
			TotalLatencyMs: total.Milliseconds(),
			Truncated:      result.Truncated,
			DetectorErrors: detectorErrorList(errs),
		},
	}
	metrics.CheckDurationSeconds.WithLabelValues("total").Observe(total.Seconds())
	metrics.CheckRequestsTotal.WithLabelValues("200").Inc()
	writeJSON(w, http.StatusOK, resp)

	a.logger.Info().
		Str("request_id", reqID).
		Str("remote_addr", r.RemoteAddr).
		Int("diff_bytes", len(diff)).
		Int("raw_findings", len(raw)).
		Int("after_dedup", len(deduped)).
		Int("confirmed", confirmed).
		Int("dismissed", dismissed).
		Bool("llm_invoked", result.LLMInvoked).
		Int("llm_calls", result.LLMCalls).
		Int64("llm_latency_ms", result.LLMLatency.Milliseconds()).
		Int64("total_ms", total.Milliseconds()).
		Bool("truncated", result.Truncated).
		Msg("check")

	a.writeAudit(reqID, r, diff, raw, deduped, &resp)
}

// Healthz is the liveness probe: it returns 200 as long as the process
// is up. Orchestrator restart loops should target /healthz, not /readyz —
// a slow LLM endpoint shouldn't trigger a pod restart.
func (a *App) Healthz(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apitypes.HealthzResponse{
		Status:       "ok",
		LLMReachable: true, // backwards compat — see /readyz for the real signal
	})
}

// Readyz is the readiness probe: it returns 200/503 based on a cached
// LLM-reachability state that a background goroutine refreshes on the
// `llm.healthcheck_interval` cadence. The cache means a busy load
// balancer can't turn /readyz into an LLM DoS amplifier; the staleness
// check inside Reachability.Ready() means a wedged watcher fails open
// to "not ready" rather than serving stale "ready" answers.
//
// Load balancers / k8s readiness should target this; a /readyz=503
// takes the pod out of the rotation but doesn't restart it.
func (a *App) Readyz(w http.ResponseWriter, r *http.Request) {
	reachable := a.reachability != nil && a.reachability.Ready()
	status := http.StatusOK
	if !reachable {
		status = http.StatusServiceUnavailable
	}
	writeJSON(w, status, apitypes.HealthzResponse{
		Status:       readyzStatus(reachable),
		LLMReachable: reachable,
	})
}

func readyzStatus(reachable bool) string {
	if reachable {
		return "ready"
	}
	return "not_ready"
}

func (a *App) Version(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, apitypes.VersionResponse{
		Atalaia:    a.version,
		LLMModel:   a.config.LLM.Model,
		Gitleaks:   "unknown",
		Trufflehog: "unknown",
		Kingfisher: "unknown",
	})
}

// writeAudit fans the just-finished response out to the audit sink.
// Raw matches are populated only when observability.audit.reveal_matches
// is true — otherwise entries carry preview only.
func (a *App) writeAudit(reqID string, r *http.Request, diff []byte, raw []detector.Finding, deduped []detector.DedupedFinding, resp *apitypes.CheckResponse) {
	if a.audit == nil {
		return
	}
	reveal := a.config.Observability.Audit.RevealMatches

	matchByID := map[string]string{}
	for _, d := range deduped {
		matchByID[d.ID] = d.Match
	}

	verdicts := make([]audit.Verdict, len(resp.Verdicts))
	for i, v := range resp.Verdicts {
		av := audit.Verdict{
			ID:           v.ID,
			File:         v.File,
			Line:         v.Line,
			MatchPreview: v.MatchPreview,
			Verdict:      v.Verdict,
			Confidence:   v.Confidence,
			Reason:       v.Reason,
		}
		if reveal {
			av.Match = matchByID[v.ID]
		}
		verdicts[i] = av
	}

	entry := audit.Entry{
		RequestID:    reqID,
		RemoteAddr:   r.RemoteAddr,
		DiffBytes:    len(diff),
		DetectorsRun: resp.Stats.DetectorsRun,
		RawFindings:  resp.Stats.RawFindings,
		AfterDedup:   resp.Stats.AfterDedup,
		Confirmed:    resp.Stats.Confirmed,
		Dismissed:    resp.Stats.Dismissed,
		LLMInvoked:   resp.Stats.LLMInvoked,
		LLMCalls:     resp.Stats.LLMCalls,
		LLMModel:     resp.Stats.LLMModel,
		LLMLatencyMs: resp.Stats.LLMLatencyMs,
		TotalMs:      resp.Stats.TotalLatencyMs,
		Truncated:    resp.Stats.Truncated,
		Verdicts:     verdicts,
	}
	if err := a.audit.Write(entry); err != nil {
		a.logger.Error().Str("request_id", reqID).Err(err).Msg("audit write failed")
	}
}

// mergeVerdicts joins llm verdicts back to dedup'd findings (which own
// the file/line/preview/detections fields). The Adjudicator guarantees
// one verdict per finding, so missing entries fall through to the
// safe-fallback shape — this should not happen in practice, but the
// API contract still demands a verdict per finding.
func mergeVerdicts(deduped []detector.DedupedFinding, decisions []llm.Verdict) []apitypes.Verdict {
	byID := make(map[string]llm.Verdict, len(decisions))
	for _, v := range decisions {
		byID[v.FindingID] = v
	}

	out := make([]apitypes.Verdict, 0, len(deduped))
	for _, d := range deduped {
		v, ok := byID[d.ID]
		if !ok {
			v = llm.Verdict{
				FindingID:  d.ID,
				Verdict:    apitypes.VerdictConfirmed,
				Confidence: 0,
				Reason:     "no verdict produced for this finding",
			}
		}
		out = append(out, apitypes.Verdict{
			ID:           d.ID,
			File:         d.File,
			Line:         d.Line,
			MatchPreview: redact.Preview(d.Match),
			Verdict:      v.Verdict,
			Confidence:   v.Confidence,
			Reason:       v.Reason,
			Detections:   convertDetections(d.Detections),
		})
	}
	return out
}

func countVerdicts(vs []apitypes.Verdict) (confirmed, dismissed int) {
	for _, v := range vs {
		switch v.Verdict {
		case apitypes.VerdictConfirmed:
			confirmed++
		case apitypes.VerdictDismissed:
			dismissed++
		}
	}
	return
}

// readDiff handles both `text/x-diff` (raw unified diff) and
// `application/json` with `{"diff": "..."}`. Body size is capped by
// server.max_body_bytes; anything larger errors before we read the
// tail of the request.
func readDiff(r *http.Request, max int64) ([]byte, error) {
	body := r.Body
	if max > 0 {
		body = http.MaxBytesReader(nil, r.Body, max)
	}
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))

	switch ct {
	case "application/json":
		var req apitypes.CheckRequest
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			return nil, &httpError{"invalid JSON body: " + err.Error()}
		}
		if req.Diff == "" {
			return nil, &httpError{"missing diff field"}
		}
		return []byte(req.Diff), nil
	case "", "text/x-diff", "text/plain", "application/x-patch":
		b, err := io.ReadAll(body)
		if err != nil {
			return nil, &httpError{"reading body: " + err.Error()}
		}
		if len(b) == 0 {
			return nil, &httpError{"empty body"}
		}
		return b, nil
	default:
		return nil, &httpError{"unsupported content-type: " + ct}
	}
}

type httpError struct{ msg string }

func (e *httpError) Error() string { return e.msg }

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apitypes.ErrorResponse{Error: msg})
}

func convertDetections(in []detector.Detection) []apitypes.Detection {
	out := make([]apitypes.Detection, len(in))
	for i, d := range in {
		out[i] = apitypes.Detection{
			DetectorType: d.DetectorType,
			DetectorName: d.DetectorName,
			Rule:         d.Rule,
			Verified:     d.Verified,
		}
	}
	return out
}

func detectorNames(dets []detector.Detector) []string {
	out := make([]string, len(dets))
	for i, d := range dets {
		out[i] = d.Name()
	}
	return out
}

// detectorErrorList turns the runner's error map into a stable,
// name-sorted slice for the response stats. Returns nil when empty so
// the field is omitted from the JSON.
func detectorErrorList(errs map[string]error) []apitypes.DetectorError {
	if len(errs) == 0 {
		return nil
	}
	out := make([]apitypes.DetectorError, 0, len(errs))
	for name, err := range errs {
		out = append(out, apitypes.DetectorError{Detector: name, Error: err.Error()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Detector < out[j].Detector })
	return out
}

// detectorErrorSummary is a compact "name: err; name: err" string for
// the 503 body and the inconclusive-scan log line.
func detectorErrorSummary(errs map[string]error) string {
	parts := make([]string, 0, len(errs))
	for _, e := range detectorErrorList(errs) {
		parts = append(parts, e.Detector+": "+e.Error)
	}
	return strings.Join(parts, "; ")
}

// requestID returns the X-Request-ID header when the caller supplied
// a well-shaped value; otherwise mints a fresh ULID. Callers that
// already correlate logs across a distributed system can pass their
// own ID through; standalone callers get atalaia's ULID for free.
//
// "Well-shaped" rejects anything that could leak into logs or audit
// records badly: whitespace, control characters, non-ASCII, oversize
// payloads. The character set is intentionally narrow so the ID can
// land in a structured log line, a URL, and a JSON value without any
// escaping concerns.
func requestID(r *http.Request) string {
	if id, ok := sanitizeRequestID(r.Header.Get("X-Request-ID")); ok {
		return id
	}
	return ulid.MustNew(ulid.Now(), rand.Reader).String()
}

func sanitizeRequestID(raw string) (string, bool) {
	id := strings.TrimSpace(raw)
	if id == "" || len(id) > 128 {
		return "", false
	}
	for _, c := range id {
		switch {
		case c >= 'a' && c <= 'z',
			c >= 'A' && c <= 'Z',
			c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == ':':
		default:
			return "", false
		}
	}
	return id, true
}
