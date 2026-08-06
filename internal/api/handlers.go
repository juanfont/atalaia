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

// deepOutcome carries the deep read back from its goroutine. The error
// is handled, never returned to the caller as a failure: verdicts[] is
// the primary product and stands on its own.
type deepOutcome struct {
	result llm.DeepResult
	err    error
}

func (a *App) Check(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	reqID := requestID(r)
	w.Header().Set("X-Request-ID", reqID)

	diff, deep, err := readCheckRequest(r, a.config.Server.MaxBodyBytes)
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

	// ---- deep stage (opt-in, concurrent with adjudication) ----
	// Started before Adjudicate so the two overlap when the backend has
	// capacity. Both contend for the same LLM semaphore, so at
	// max_inflight 1 this degrades to taking turns, which is correct. A
	// deep request therefore occupies up to two queue waiters.
	var deepCh chan deepOutcome
	if deep && a.deepScanner != nil {
		deepCh = make(chan deepOutcome, 1)
		go func() {
			res, err := a.deepScanner.Scan(r.Context(), diff, len(deduped))
			deepCh <- deepOutcome{result: res, err: err}
		}()
	}

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
	confirmed, dismissed, unreviewed := countVerdicts(verdicts)
	metrics.VerdictsTotal.WithLabelValues(apitypes.VerdictConfirmed).Add(float64(confirmed))
	metrics.VerdictsTotal.WithLabelValues(apitypes.VerdictDismissed).Add(float64(dismissed))
	metrics.VerdictsTotal.WithLabelValues(apitypes.VerdictUnreviewed).Add(float64(unreviewed))

	// ---- collect the deep read ----
	// A deep failure never fails the request. It surfaces in stats so a
	// caller cannot read missing discoveries as a clean diff, the same
	// contract DetectorErrors carries.
	var (
		discoveries []apitypes.Discovery
		deepStats   *apitypes.DeepScanStats
		deepRaw     []llm.Discovery
	)
	if deep {
		deepStats = &apitypes.DeepScanStats{}
		if deepCh == nil {
			// Operator disabled deep scan. Report it rather than
			// silently answering as though it ran.
			metrics.DeepScanTotal.WithLabelValues("disabled").Inc()
		} else if outcome := <-deepCh; outcome.err != nil {
			deepStats.Error = outcome.err.Error()
			a.logger.Warn().Str("request_id", reqID).Err(outcome.err).Msg("deep scan failed")
			metrics.DeepScanTotal.WithLabelValues("error").Inc()
		} else {
			metrics.DeepScanTotal.WithLabelValues("ok").Inc()
			grounded, gstats := llm.Ground(diff, outcome.result.Candidates, deduped)
			deepRaw = grounded
			discoveries = convertDiscoveries(grounded)
			deepStats.Ran = true
			deepStats.Calls = outcome.result.Calls
			deepStats.Windows = outcome.result.Windows
			deepStats.Truncated = outcome.result.Truncated
			deepStats.LatencyMs = outcome.result.Latency.Milliseconds()
			deepStats.Candidates = gstats.Candidates
			deepStats.Discovered = gstats.Discovered
			deepStats.Ungrounded = gstats.Ungrounded
		}
	}

	total := time.Since(start)
	resp := apitypes.CheckResponse{
		RequestID:   reqID,
		Verdicts:    verdicts,
		Discoveries: discoveries,
		Stats: apitypes.Stats{
			DetectorsRun:   detectorNames(a.detectors),
			RawFindings:    len(raw),
			AfterDedup:     len(deduped),
			Confirmed:      confirmed,
			Dismissed:      dismissed,
			Unreviewed:     unreviewed,
			LLMInvoked:     result.LLMInvoked,
			LLMCalls:       result.LLMCalls,
			LLMModel:       a.config.LLM.Model,
			LLMLatencyMs:   result.LLMLatency.Milliseconds(),
			TotalLatencyMs: total.Milliseconds(),
			Truncated:      result.Truncated,
			DetectorErrors: detectorErrorList(errs),
			DeepScan:       deepStats,
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
		Bool("deep", deep).
		Int("discoveries", len(discoveries)).
		Msg("check")

	a.writeAudit(reqID, r, diff, raw, deduped, deepRaw, &resp)
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
	promptDeep := ""
	if a.deepScanner != nil {
		promptDeep = a.deepScanner.PromptFingerprint()
	}
	writeJSON(w, http.StatusOK, apitypes.VersionResponse{
		Atalaia:    a.version,
		LLMModel:   a.config.LLM.Model,
		Prompt:     a.adjudicator.PromptFingerprint(),
		PromptDeep: promptDeep,
		Gitleaks:   "unknown",
		Trufflehog: "unknown",
		Kingfisher: "unknown",
	})
}

// writeAudit fans the just-finished response out to the audit sink.
// Raw matches are populated only when observability.audit.reveal_matches
// is true — otherwise entries carry preview only.
func (a *App) writeAudit(reqID string, r *http.Request, diff []byte, raw []detector.Finding, deduped []detector.DedupedFinding, discoveries []llm.Discovery, resp *apitypes.CheckResponse) {
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

	auditDiscoveries := make([]audit.Discovery, len(discoveries))
	for i, d := range discoveries {
		ad := audit.Discovery{
			ID:           d.ID,
			File:         d.File,
			Line:         d.Line,
			MatchPreview: d.MatchPreview,
			Kind:         d.Kind,
			Confidence:   d.Confidence,
			Reason:       d.Reason,
		}
		if reveal {
			ad.Match = d.Match
		}
		auditDiscoveries[i] = ad
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
		Discoveries:  auditDiscoveries,
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
			// The model's reason occasionally quotes the matched value
			// verbatim; scrub it so the raw secret never leaves in the
			// explanation (the preview is the only value we surface).
			Reason:     redact.Scrub(v.Reason, d.Match),
			Detections: convertDetections(d.Detections),
		})
	}
	return out
}

func countVerdicts(vs []apitypes.Verdict) (confirmed, dismissed, unreviewed int) {
	for _, v := range vs {
		switch v.Verdict {
		case apitypes.VerdictConfirmed:
			confirmed++
		case apitypes.VerdictDismissed:
			dismissed++
		case apitypes.VerdictUnreviewed:
			unreviewed++
		}
	}
	return
}

// readCheckRequest handles both `text/x-diff` (raw unified diff) and
// `application/json` with `{"diff": "...", "deep": bool}`. Body size is
// capped by server.max_body_bytes; anything larger errors before we
// read the tail of the request.
//
// deep opts into the second LLM pass. The raw content types have no
// place to carry it in the body, so they use ?deep=1. JSON callers may
// use either.
func readCheckRequest(r *http.Request, max int64) (diff []byte, deep bool, err error) {
	body := r.Body
	if max > 0 {
		body = http.MaxBytesReader(nil, r.Body, max)
	}
	ct := r.Header.Get("Content-Type")
	if i := strings.Index(ct, ";"); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(strings.ToLower(ct))

	q := r.URL.Query().Get("deep")
	queryDeep := q == "1" || q == "true"

	switch ct {
	case "application/json":
		var req apitypes.CheckRequest
		if err := json.NewDecoder(body).Decode(&req); err != nil {
			return nil, false, &httpError{"invalid JSON body: " + err.Error()}
		}
		if req.Diff == "" {
			return nil, false, &httpError{"missing diff field"}
		}
		return []byte(req.Diff), req.Deep || queryDeep, nil
	case "", "text/x-diff", "text/plain", "application/x-patch":
		b, err := io.ReadAll(body)
		if err != nil {
			return nil, false, &httpError{"reading body: " + err.Error()}
		}
		if len(b) == 0 {
			return nil, false, &httpError{"empty body"}
		}
		return b, queryDeep, nil
	default:
		return nil, false, &httpError{"unsupported content-type: " + ct}
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

// convertDiscoveries maps grounded discoveries to the wire shape. The
// raw Match never crosses this boundary: only the preview does.
func convertDiscoveries(in []llm.Discovery) []apitypes.Discovery {
	if len(in) == 0 {
		return nil
	}
	out := make([]apitypes.Discovery, len(in))
	for i, d := range in {
		out[i] = apitypes.Discovery{
			ID:           d.ID,
			File:         d.File,
			Line:         d.Line,
			MatchPreview: d.MatchPreview,
			Kind:         d.Kind,
			Confidence:   d.Confidence,
			Reason:       d.Reason,
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
