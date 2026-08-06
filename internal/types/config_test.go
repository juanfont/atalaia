package types

import (
	"strings"
	"testing"
	"time"

	"github.com/spf13/viper"
)

func resetViper() {
	viper.Reset()
}

func TestConfig_MinimalIsValid(t *testing.T) {
	resetViper()
	if err := ReadViperConfig("testdata/minimal.yaml", true); err != nil {
		t.Fatalf("ReadViperConfig: %v", err)
	}
	cfg, err := GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.Server.Listen != "127.0.0.1:8080" {
		t.Errorf("Server.Listen = %q, want 127.0.0.1:8080", cfg.Server.Listen)
	}
	if cfg.LLM.RequestTimeout != 7*time.Second {
		t.Errorf("LLM.RequestTimeout = %v, want 7s (duration parsing)", cfg.LLM.RequestTimeout)
	}
	if cfg.LLM.MaxInflight != 1 {
		t.Errorf("LLM.MaxInflight = %d, want 1 (default)", cfg.LLM.MaxInflight)
	}
}

func TestConfig_MissingListenFails(t *testing.T) {
	resetViper()
	if err := ReadViperConfig("testdata/missing-listen.yaml", true); err != nil {
		t.Fatalf("ReadViperConfig: %v", err)
	}
	_, err := GetConfig()
	if err == nil {
		t.Fatal("expected validation error for empty server.listen")
	}
	if !strings.Contains(err.Error(), "server.listen") {
		t.Errorf("error %q does not mention server.listen", err)
	}
}

func TestConfig_MissingEndpointFails(t *testing.T) {
	resetViper()
	if err := ReadViperConfig("testdata/missing-endpoint.yaml", true); err != nil {
		t.Fatalf("ReadViperConfig: %v", err)
	}
	_, err := GetConfig()
	if err == nil {
		t.Fatal("expected validation error for missing llm.endpoint")
	}
	if !strings.Contains(err.Error(), "llm.endpoint") {
		t.Errorf("error %q does not mention llm.endpoint", err)
	}
}

func TestConfig_EnvOverride(t *testing.T) {
	resetViper()
	t.Setenv("ATALAIA_LLM_ENDPOINT", "http://overridden:9000/v1")
	if err := ReadViperConfig("testdata/minimal.yaml", true); err != nil {
		t.Fatalf("ReadViperConfig: %v", err)
	}
	cfg, err := GetConfig()
	if err != nil {
		t.Fatalf("GetConfig: %v", err)
	}
	if cfg.LLM.Endpoint != "http://overridden:9000/v1" {
		t.Errorf("LLM.Endpoint = %q, want override from env", cfg.LLM.Endpoint)
	}
}

func TestValidateAuthKeyNotInFile_RejectsLiteral(t *testing.T) {
	err := ValidateAuthKeyNotInFile("testdata/auth-key-in-yaml.yaml")
	if err == nil {
		t.Fatal("expected error for tailscale.auth_key in YAML")
	}
	if !strings.Contains(err.Error(), "ATALAIA_TAILSCALE_AUTH_KEY") {
		t.Errorf("error message should point at the env var, got %q", err)
	}
}

func TestValidateAuthKeyNotInFile_AcceptsClean(t *testing.T) {
	if err := ValidateAuthKeyNotInFile("testdata/minimal.yaml"); err != nil {
		t.Errorf("clean YAML should pass, got %v", err)
	}
}

func TestValidateAuthKeyNotInFile_EmptyPath(t *testing.T) {
	if err := ValidateAuthKeyNotInFile(""); err != nil {
		t.Errorf("empty path should be no-op, got %v", err)
	}
}

func TestConfig_UnknownDetectorFails(t *testing.T) {
	resetViper()
	if err := ReadViperConfig("testdata/minimal.yaml", true); err != nil {
		t.Fatalf("ReadViperConfig: %v", err)
	}
	viper.Set("detectors.enabled", []string{"gitleaks", "nope"})
	_, err := GetConfig()
	if err == nil {
		t.Fatal("expected validation error for unknown detector")
	}
	if !strings.Contains(err.Error(), "unknown detector") {
		t.Errorf("error %q does not mention unknown detector", err)
	}
}

func TestReadLLMConfig_DeepScanDefaults(t *testing.T) {
	resetViper()
	setDefaults()

	c := readLLMConfig()

	if c.DeepScan.Enabled {
		t.Errorf("deep scan must default off, got enabled")
	}
	if c.DeepScan.MaxWindows != 8 {
		t.Errorf("max_windows default = %d, want 8", c.DeepScan.MaxWindows)
	}
	if c.DeepScan.MaxCandidates != 50 {
		t.Errorf("max_candidates default = %d, want 50", c.DeepScan.MaxCandidates)
	}
	if c.DeepScan.Profile != "gemma4_deep" {
		t.Errorf("profile default = %q, want gemma4_deep", c.DeepScan.Profile)
	}
	if c.DeepScan.RequireFindings {
		t.Errorf("require_findings must default off")
	}
}

// deepScanTestConfig is a config that passes validateConfig, so a test
// can flip one deep-scan field and see only that field's error.
func deepScanTestConfig() *Config {
	return &Config{
		Server: ServerConfig{Listen: "127.0.0.1:8080"},
		LLM: LLMConfig{
			Endpoint:    "http://127.0.0.1:8000/v1",
			Model:       "test-model",
			MaxInflight: 1,
			QueueMax:    16,
			Profile:     "gemma4",
			Profiles: map[string]LLMProfile{
				"gemma4": {SystemTemplate: "s.tmpl", UserTemplate: "u.tmpl"},
			},
		},
	}
}

func TestValidateConfig_DeepScanProfileMustExist(t *testing.T) {
	cfg := deepScanTestConfig()
	cfg.LLM.DeepScan.Enabled = true
	cfg.LLM.DeepScan.Profile = "nope"

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("want error for deep scan profile that is not configured")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Errorf("error should name the missing profile, got %v", err)
	}
}

func TestValidateConfig_DeepScanProfileNeedsTemplates(t *testing.T) {
	cfg := deepScanTestConfig()
	cfg.LLM.Profiles["gemma4_deep"] = LLMProfile{}
	cfg.LLM.DeepScan.Enabled = true
	cfg.LLM.DeepScan.Profile = "gemma4_deep"

	err := validateConfig(cfg)
	if err == nil {
		t.Fatal("want error for deep profile with no templates")
	}
	if !strings.Contains(err.Error(), "system_template") {
		t.Errorf("error should name the missing templates, got %v", err)
	}
}

func TestValidateConfig_DeepScanDisabledSkipsProfileCheck(t *testing.T) {
	cfg := deepScanTestConfig()
	cfg.LLM.DeepScan.Enabled = false
	cfg.LLM.DeepScan.Profile = "nope"

	if err := validateConfig(cfg); err != nil {
		t.Errorf("disabled deep scan must not validate its profile, got %v", err)
	}
}
