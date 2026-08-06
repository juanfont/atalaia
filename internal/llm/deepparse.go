package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

type rawCandidate struct {
	Value      string  `json:"value"`
	Kind       string  `json:"kind"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

// stripCodeFence removes a leading ```json / ``` fence and its closer,
// and trims surrounding whitespace. Shared by both response parsers:
// models wrap JSON in markdown regardless of which schema they were
// handed.
func stripCodeFence(raw string) string {
	body := strings.TrimSpace(raw)
	if strings.HasPrefix(body, "```") {
		if i := strings.IndexByte(body, '\n'); i >= 0 {
			body = body[i+1:]
		}
		body = strings.TrimSuffix(strings.TrimSpace(body), "```")
		body = strings.TrimSpace(body)
	}
	return body
}

// parseDeepToolCalls reads candidates out of the tool-calling path.
// Calls for other tools are ignored: a model that also emits chatter
// should not fail the read. Unlike the verdict path, no tool call at
// all is not an error. "I found nothing" is the common answer, and
// some models express it by simply not calling the tool.
func parseDeepToolCalls(calls []ToolCall) ([]DeepCandidate, error) {
	var out []DeepCandidate
	for _, c := range calls {
		if c.Function.Name != DeepToolName {
			continue
		}
		got, err := parseDeepResponse(c.Function.Arguments)
		if err != nil {
			return nil, fmt.Errorf("tool call %s: %w", DeepToolName, err)
		}
		out = append(out, got...)
	}
	return out, nil
}

// parseDeepResponse decodes the JSON the model produced. It tolerates
// the same shapes as parseVerdictResponse: fenced blocks, the
// {"candidates":[...]} envelope, and a bare top-level array.
//
// An empty body is not an error. Most diffs contain no secrets, so
// "nothing here" is the expected answer and must not fail the request.
func parseDeepResponse(raw string) ([]DeepCandidate, error) {
	body := stripCodeFence(raw)
	if body == "" {
		return nil, nil
	}

	var cands []rawCandidate
	switch {
	case strings.HasPrefix(body, "["):
		if err := json.Unmarshal([]byte(body), &cands); err != nil {
			return nil, err
		}
	case strings.HasPrefix(body, "{"):
		var envelope struct {
			Candidates []rawCandidate `json:"candidates"`
		}
		if err := json.Unmarshal([]byte(body), &envelope); err != nil {
			return nil, err
		}
		cands = envelope.Candidates
	default:
		return nil, fmt.Errorf("response is neither a JSON object nor array")
	}

	out := make([]DeepCandidate, 0, len(cands))
	for _, c := range cands {
		if strings.TrimSpace(c.Value) == "" {
			continue
		}
		out = append(out, DeepCandidate{
			Value:      c.Value,
			Kind:       c.Kind,
			Confidence: c.Confidence,
			Reason:     c.Reason,
		})
	}
	return out, nil
}
