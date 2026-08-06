package apitypes

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// TestCheckResponseRoundtrip locks down the wire shape: a known-good
// payload decodes into typed structs and re-encodes byte-for-byte
// identical (after canonicalising whitespace through a JSON
// round-trip). Catches accidental tag drift in two-years-from-now
// refactors.
func TestCheckResponseRoundtrip(t *testing.T) {
	const sample = `{
  "request_id": "01KRN34HMPNN6823H2676YF37A",
  "verdicts": [
    {
      "id": "78292567e712",
      "file": "keys.py",
      "line": 4,
      "match_preview": "AKIA****IJKL",
      "verdict": "dismissed",
      "confidence": 1,
      "reason": "Documentation example.",
      "detections": [
        {
          "detector_type": "gitleaks",
          "detector_name": "generic-api-key",
          "rule": "generic-api-key",
          "verified": false
        },
        {
          "detector_type": "trufflehog",
          "detector_name": "aws",
          "rule": "aws",
          "verified": true
        }
      ]
    }
  ],
  "stats": {
    "detectors_run": ["gitleaks", "trufflehog"],
    "raw_findings": 2,
    "after_dedup": 1,
    "confirmed": 0,
    "dismissed": 1,
    "unreviewed": 0,
    "llm_invoked": true,
    "llm_calls": 1,
    "llm_model": "google/gemma-4-E4B-it",
    "llm_latency_ms": 1804,
    "total_latency_ms": 1805,
    "truncated": false
  }
}`

	var decoded CheckResponse
	if err := json.Unmarshal([]byte(sample), &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Spot-check the unmarshal landed in the right fields.
	if decoded.RequestID != "01KRN34HMPNN6823H2676YF37A" {
		t.Errorf("RequestID=%q", decoded.RequestID)
	}
	if len(decoded.Verdicts) != 1 {
		t.Fatalf("verdicts=%d", len(decoded.Verdicts))
	}
	v := decoded.Verdicts[0]
	if v.Verdict != VerdictDismissed || v.Confidence != 1 {
		t.Errorf("verdict shape: %+v", v)
	}
	if len(v.Detections) != 2 || !v.Detections[1].Verified {
		t.Errorf("detections shape: %+v", v.Detections)
	}
	if decoded.Stats.LLMLatencyMs != 1804 || decoded.Stats.AfterDedup != 1 {
		t.Errorf("stats shape: %+v", decoded.Stats)
	}

	// Round-trip: marshal the typed value back, decode as a generic
	// map, and compare to a generic map decoded from the original
	// sample. JSON-tag drift, dropped fields, or type confusion all
	// surface as a non-equal map. Field ordering doesn't matter (map
	// comparison is unordered).
	got, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("re-marshal: %v", err)
	}
	var gotMap, wantMap map[string]any
	if err := json.Unmarshal(got, &gotMap); err != nil {
		t.Fatalf("re-unmarshal: %v", err)
	}
	if err := json.Unmarshal([]byte(sample), &wantMap); err != nil {
		t.Fatalf("sample unmarshal: %v", err)
	}
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Errorf("wire shape drifted.\n got=%v\nwant=%v", gotMap, wantMap)
	}
}

func TestErrorResponseRoundtrip(t *testing.T) {
	const sample = `{"error":"upstream timeout"}`
	var e ErrorResponse
	if err := json.Unmarshal([]byte(sample), &e); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if e.Error != "upstream timeout" {
		t.Errorf("Error=%q", e.Error)
	}
	got, _ := json.Marshal(e)
	if string(got) != sample {
		t.Errorf("re-marshal=%s, want %s", got, sample)
	}
}

func TestHealthzAndVersionTags(t *testing.T) {
	h, _ := json.Marshal(HealthzResponse{Status: "ok", LLMReachable: true})
	if string(h) != `{"status":"ok","llm_reachable":true}` {
		t.Errorf("healthz tags drift: %s", h)
	}
	v, _ := json.Marshal(VersionResponse{Atalaia: "x", LLMModel: "m", Prompt: "gemma4:abc", Gitleaks: "?", Trufflehog: "?", Kingfisher: "?"})
	if string(v) != `{"atalaia":"x","llm_model":"m","prompt":"gemma4:abc","gitleaks":"?","trufflehog":"?","kingfisher":"?"}` {
		t.Errorf("version tags drift: %s", v)
	}
}

func TestCheckResponse_OmitsDiscoveriesWhenAbsent(t *testing.T) {
	b, err := json.Marshal(CheckResponse{RequestID: "r1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "discoveries") {
		t.Errorf("discoveries must be omitted when nil: %s", b)
	}
	if strings.Contains(string(b), "deep_scan") {
		t.Errorf("deep_scan stats must be omitted when nil: %s", b)
	}
}

func TestDiscovery_JSONShape(t *testing.T) {
	b, err := json.Marshal(Discovery{
		ID:           "abc123",
		File:         "src/app.go",
		Line:         42,
		MatchPreview: "AKIA...MPLE",
		Kind:         KindCredential,
		Confidence:   0.9,
		Reason:       "hardcoded provider key",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"id":"abc123"`, `"file":"src/app.go"`, `"line":42`,
		`"match_preview":"AKIA...MPLE"`, `"kind":"credential"`,
		`"confidence":0.9`, `"reason":"hardcoded provider key"`,
	} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if strings.Contains(string(b), "verdict") {
		t.Errorf("Discovery must carry no verdict field: %s", b)
	}
	if strings.Contains(string(b), "detections") {
		t.Errorf("Discovery must carry no detections field: %s", b)
	}
}

func TestCheckRequest_DeepFlag(t *testing.T) {
	var req CheckRequest
	if err := json.Unmarshal([]byte(`{"diff":"d","deep":true}`), &req); err != nil {
		t.Fatal(err)
	}
	if !req.Deep {
		t.Error("deep flag did not decode")
	}
}

func TestVersionResponse_OmitsPromptDeepWhenEmpty(t *testing.T) {
	b, err := json.Marshal(VersionResponse{Atalaia: "v1"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "prompt_deep") {
		t.Errorf("prompt_deep must be omitted when deep scan is off: %s", b)
	}
}
