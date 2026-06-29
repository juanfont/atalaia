package llm

// VerdictSchema is the JSON schema we hand to the LLM backend via
// `response_format: {"type":"json_schema", ...}`. With strict-mode
// guided decoding, malformed model output is structurally impossible;
// gap-filling in Adjudicate handles the remaining semantic failures
// (missing finding_id, blank reason, refusals).
//
// Kept as Go literals (not a JSON string) so the compiler validates
// the shape and dev tooling can refactor field names.
var VerdictSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"verdicts": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"finding_id": map[string]any{"type": "string"},
					"verdict": map[string]any{
						"type": "string",
						"enum": []string{"confirmed", "dismissed"},
					},
					"confidence": map[string]any{
						"type":    "number",
						"minimum": 0,
						"maximum": 1,
					},
					"reason": map[string]any{
						"type":      "string",
						"maxLength": 280,
					},
				},
				"required":             []string{"finding_id", "verdict", "confidence", "reason"},
				"additionalProperties": false,
			},
		},
	},
	"required":             []string{"verdicts"},
	"additionalProperties": false,
}

// ResponseFormat returns the OpenAI / vLLM `response_format` object
// referencing VerdictSchema. strict mode is intentionally off: with
// some vLLM + xgrammar combinations strict can wedge the decoder in a
// degenerate whitespace loop when the model emits required properties
// out of declared order. The schema itself still constrains the
// output shape; Adjudicate.parseVerdictResponse and mergeAndFill
// handle anything the schema misses.
func ResponseFormat() map[string]any {
	return map[string]any{
		"type": "json_schema",
		"json_schema": map[string]any{
			"name":   "atalaia_verdicts",
			"schema": VerdictSchema,
		},
	}
}

// VerdictToolName is the function name atalaia advertises when the
// tool-calling path is enabled. Models that support tool calls
// (Gemma 4, Qwen 2.5, Mistral with the matching parser) invoke this
// to submit the adjudicated verdicts. The function arguments match
// VerdictSchema, so the parser is shared.
const VerdictToolName = "submit_verdicts"

// VerdictTool returns the tool definition used when llm.use_tools is
// on. Tool-call mode is the principled fix for backends that drop
// fields when asked for free-form JSON: the schema is enforced by
// the function-calling machinery, not by prompt engineering.
func VerdictTool() Tool {
	return Tool{
		Type: "function",
		Function: ToolFunction{
			Name:        VerdictToolName,
			Description: "Submit one verdict per finding_id from the input. confirmed = real credential; dismissed = false positive (test fixture, doc example, placeholder, pattern collision).",
			Parameters:  VerdictSchema,
		},
	}
}

const (
	VerdictConfirmed = "confirmed"
	VerdictDismissed = "dismissed"
	// VerdictUnreviewed marks a finding the model returned no usable
	// verdict for; the gap-fill in mergeAndFill uses it instead of a
	// false "confirmed" so a model hiccup doesn't read as a credential.
	VerdictUnreviewed = "unreviewed"
)
