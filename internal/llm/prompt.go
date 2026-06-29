package llm

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"text/template"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/types"
)

// PromptTemplate holds parsed system + user templates for one profile.
// The schema is the contract; the prompt body is profile-specific and
// expected to drift as models change.
type PromptTemplate struct {
	system      *template.Template
	user        *template.Template
	fingerprint string
}

// LoadPromptTemplate loads the template files for cfg.Profile from
// cfg.Profiles[profile].{System,User}Template. Both paths are required.
func LoadPromptTemplate(cfg types.LLMConfig) (*PromptTemplate, error) {
	profile, ok := cfg.Profiles[cfg.Profile]
	if !ok {
		return nil, fmt.Errorf("llm.profiles.%s: profile not configured", cfg.Profile)
	}
	if profile.SystemTemplate == "" || profile.UserTemplate == "" {
		return nil, fmt.Errorf("llm.profiles.%s: system_template and user_template are required", cfg.Profile)
	}

	system, sysBody, err := parseFile("system", profile.SystemTemplate)
	if err != nil {
		return nil, err
	}
	user, userBody, err := parseFile("user", profile.UserTemplate)
	if err != nil {
		return nil, err
	}
	return &PromptTemplate{
		system:      system,
		user:        user,
		fingerprint: fingerprint(cfg.Profile, sysBody, userBody),
	}, nil
}

// fingerprint is a stable "profile:hash" identifier for the loaded
// prompt bodies. /version surfaces it so an operator can tell at a
// glance which prompt is actually live — a stale on-disk template
// (e.g. a deploy that updated the binary but not prompts/) changes the
// hash, making the drift detectable instead of silent.
func fingerprint(profile string, system, user []byte) string {
	h := sha256.New()
	h.Write(system)
	h.Write([]byte{0})
	h.Write(user)
	return profile + ":" + hex.EncodeToString(h.Sum(nil))[:12]
}

// Fingerprint returns the loaded prompt's "profile:hash" identifier.
func (p *PromptTemplate) Fingerprint() string { return p.fingerprint }

func parseFile(role, path string) (*template.Template, []byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s template %q: %w", role, path, err)
	}
	t, err := template.New(role).Parse(string(body))
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s template %q: %w", role, path, err)
	}
	return t, body, nil
}

// PromptData is what the user template iterates over.
type PromptData struct {
	Diff     string
	Findings []PromptFinding
}

type PromptFinding struct {
	ID         string
	File       string
	Line       int
	Match      string
	Detections []detector.Detection
	// Context, when non-empty, is the surrounding-code block the
	// template emits in per-finding mode. Whole-diff mode leaves
	// this empty and relies on PromptData.Diff instead.
	Context string
}

// Render returns the system and user messages for one LLM call.
func (p *PromptTemplate) Render(data PromptData) (system, user string, err error) {
	var sb, ub bytes.Buffer
	if err := p.system.Execute(&sb, data); err != nil {
		return "", "", fmt.Errorf("execute system template: %w", err)
	}
	if err := p.user.Execute(&ub, data); err != nil {
		return "", "", fmt.Errorf("execute user template: %w", err)
	}
	return sb.String(), ub.String(), nil
}

// findingsFromDeduped converts the detector layer's DedupedFinding
// slice into the shape the templates iterate over.
func findingsFromDeduped(in []detector.DedupedFinding) []PromptFinding {
	out := make([]PromptFinding, len(in))
	for i, d := range in {
		out[i] = PromptFinding{
			ID:         d.ID,
			File:       d.File,
			Line:       d.Line,
			Match:      clampStr(d.Match, maxMatchChars),
			Detections: d.Detections,
		}
	}
	return out
}
