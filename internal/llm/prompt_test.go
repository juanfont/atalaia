package llm

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/types"
)

func writeTmpl(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

func TestLoadPromptTemplate_Renders(t *testing.T) {
	dir := t.TempDir()
	sysPath := writeTmpl(t, dir, "sys.tmpl", "SYSTEM PROMPT")
	usrPath := writeTmpl(t, dir, "usr.tmpl",
		"diff={{.Diff}} {{range .Findings}}[{{.ID}}:{{.File}}:{{.Line}}:{{.Match}}]{{end}}")

	cfg := types.LLMConfig{
		Profile: "test",
		Profiles: map[string]types.LLMProfile{
			"test": {SystemTemplate: sysPath, UserTemplate: usrPath},
		},
	}
	tmpl, err := LoadPromptTemplate(cfg)
	if err != nil {
		t.Fatalf("LoadPromptTemplate: %v", err)
	}
	sys, usr, err := tmpl.Render(PromptData{
		Diff: "DIFF",
		Findings: []PromptFinding{
			{ID: "abc", File: "f.py", Line: 7, Match: "MATCH",
				Detections: []detector.Detection{{DetectorType: "gitleaks", Rule: "r"}}},
		},
	})
	if err != nil {
		t.Fatalf("Render: %v", err)
	}
	if sys != "SYSTEM PROMPT" {
		t.Errorf("system=%q, want SYSTEM PROMPT", sys)
	}
	if !strings.Contains(usr, "diff=DIFF") || !strings.Contains(usr, "[abc:f.py:7:MATCH]") {
		t.Errorf("user prompt missing expected fields: %q", usr)
	}
}

func TestLoadPromptTemplate_MissingProfile(t *testing.T) {
	cfg := types.LLMConfig{Profile: "nope", Profiles: map[string]types.LLMProfile{}}
	if _, err := LoadPromptTemplate(cfg); err == nil {
		t.Error("expected error for missing profile")
	}
}

func TestLoadPromptTemplate_BlankPathRequired(t *testing.T) {
	cfg := types.LLMConfig{
		Profile: "test",
		Profiles: map[string]types.LLMProfile{
			"test": {SystemTemplate: "", UserTemplate: "x"},
		},
	}
	if _, err := LoadPromptTemplate(cfg); err == nil {
		t.Error("expected error for blank system_template")
	}
}
