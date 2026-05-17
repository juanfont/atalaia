// Package apitypes exposes the Go types for Atalaia's HTTP API.
//
// It exists so external consumers (webhook watchers, CI gates,
// pre-commit harnesses) can decode /check responses into typed
// structs without redefining the schema by hand. Everything in this
// package mirrors a JSON shape Atalaia emits over the wire.
//
// # The JSON shape is the contract
//
// The stable thing is the JSON: field names, types, nesting. Go
// identifiers (CheckResponse, Verdict.MatchPreview, …) are
// convenience. Renaming a Go field while leaving the JSON tag intact
// is fine; changing a JSON tag or removing a field changes the wire
// contract.
//
// # Dependencies
//
// Stdlib only. No third-party imports, no dependency on Atalaia's
// internal packages, and no transitive pull-in of gitleaks, vLLM
// SDKs, viper, or any other server-side weight. Consumers can `go
// get` this package cheaply.
//
// # What's here
//
//   - CheckRequest:    POST /check JSON body (when Content-Type is
//     application/json; text/x-diff bodies are raw
//     and don't need this struct).
//   - CheckResponse:   POST /check 200 response: request_id, verdicts,
//     stats.
//   - Verdict:         one decision per dedup'd finding.
//   - Detection:       per-verdict trail of which raw detectors fired
//     on that (file, line, match).
//   - Stats:           per-request counts and timings.
//   - HealthzResponse / VersionResponse: GET /healthz, GET /readyz,
//     GET /version bodies.
//   - ErrorResponse:   the {"error": "..."} shape returned on non-2xx.
//   - Verdict* constants: the legal values of Verdict.Verdict.
//
// What's not here: anything from internal/detector, internal/llm, or
// internal/redact. Those are server-implementation details.
package apitypes
