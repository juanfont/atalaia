package llm

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"unicode/utf8"
)

const (
	maxSourceLiterals     = 32
	maxSourceLiteralBytes = 512
	maxSourceCatalogBytes = 4096
)

// SourceLiteral binds a model-selectable ID to unchanged source bytes. IDs
// refer to values within one window; they never represent model-supplied locations.
type SourceLiteral struct {
	ID    string `json:"id"`
	Value string `json:"value"`
}

func (s SourceLiteral) JSON() string {
	b, _ := json.Marshal(s.Value)
	return string(b)
}

// sourceLiterals lexes closed quoted strings without evaluating any escapes.
// A catalog entry is not a secret finding. Raw source remains in the window,
// including strings omitted because of syntax or size limits.
func sourceLiterals(window string) []SourceLiteral {
	var out []SourceLiteral
	seen := map[string]bool{}
	for _, line := range strings.Split(window, "\n") {
		if strings.HasPrefix(line, deepWindowHeader) {
			continue
		}
		for i := 0; i < len(line); {
			q := line[i]
			if q != '\'' && q != '"' {
				i++
				continue
			}
			start := i + 1
			i++
			for i < len(line) {
				if line[i] == '\\' {
					i += 2
					continue
				}
				if line[i] != q {
					i++
					continue
				}
				value := line[start:i]
				i++
				if !utf8.ValidString(value) || len(value) > maxSourceLiteralBytes || !strings.Contains(value, "\\") || seen[value] {
					break
				}
				entry := SourceLiteral{ID: fmt.Sprintf("literal_%d", len(out)+1), Value: value}
				proposed := append(out, entry)
				encoded, _ := json.Marshal(proposed)
				if len(encoded) > maxSourceCatalogBytes {
					break
				}
				out = proposed
				seen[value] = true
				if len(out) == maxSourceLiterals {
					return out
				}
				break
			}
		}
	}
	return out
}

func sourceValue(sources []SourceLiteral, id string) (string, bool) {
	for _, source := range sources {
		if source.ID == id {
			return source.Value, true
		}
	}
	return "", false
}

// deepToolWithSources adds an alternative to copying bytes without mutating
// the shared default schema used by concurrent requests and older profiles.
func deepToolWithSources(sources []SourceLiteral) Tool {
	tool := DeepTool()
	if len(sources) == 0 {
		return tool
	}
	root := maps.Clone(DeepSchema)
	props := maps.Clone(root["properties"].(map[string]any))
	candidates := maps.Clone(props["candidates"].(map[string]any))
	item := maps.Clone(candidates["items"].(map[string]any))
	fields := maps.Clone(item["properties"].(map[string]any))
	ids := make([]string, len(sources))
	for i, source := range sources {
		ids[i] = source.ID
	}
	fields["source_id"] = map[string]any{"type": "string", "enum": ids}
	item["properties"] = fields
	item["required"] = []string{"kind", "confidence", "reason"}
	item["anyOf"] = []any{map[string]any{"required": []string{"value"}}, map[string]any{"required": []string{"source_id"}}}
	candidates["items"] = item
	props["candidates"] = candidates
	root["properties"] = props
	tool.Function.Parameters = root
	tool.Function.Description += " For an escaped literal in the source catalog, submit its source_id instead of copying value. Catalog membership does not establish credential status."
	return tool
}

// sourceCatalogPrompt is appended only when the option is enabled and the
// catalog fits. Every profile gets the value bindings advertised in its schema.
func sourceCatalogPrompt(sources []SourceLiteral) string {
	if len(sources) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nEscaped source literal catalog (JSON encoding of exact source spelling):\n")
	for _, source := range sources {
		fmt.Fprintf(&b, "%s: %s\n", source.ID, source.JSON())
	}
	b.WriteString("For a catalogued literal, return source_id instead of value. The server resolves the ID to unchanged source bytes. Do not copy or decode its value. For other credentials return value as usual. Classify each normally; catalog membership alone is not evidence of a credential. Never invent an ID.\n")
	b.WriteString(`Candidate shape for a catalogued literal: {"source_id":"<ID from the catalog>","kind":"credential"|"private_key"|"test_data","confidence":0..1,"reason":"<context without credential bytes>"}`)
	return b.String()
}
