package types

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/viper"
	"go.yaml.in/yaml/v3"
)

const (
	JSONLogFormat = "json"
	TextLogFormat = "text"
)

type Config struct {
	Server        ServerConfig
	Detectors     DetectorsConfig
	LLM           LLMConfig
	Observability ObservabilityConfig
	Tailscale     TailscaleConfig
	Log           LogConfig
}

type ServerConfig struct {
	Listen       string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
	MaxBodyBytes int64
	// AuthToken, when non-empty, gates /check with
	// Authorization: Bearer <token>. /healthz, /readyz, /version stay
	// open so orchestrator probes work without secrets. Set this via
	// the environment (ATALAIA_SERVER_AUTH_TOKEN) — never the YAML.
	AuthToken string
}

type DetectorsConfig struct {
	Enabled         []string
	ParallelTimeout time.Duration
	Gitleaks        GitleaksConfig
	Trufflehog      TrufflehogConfig
	Kingfisher      KingfisherConfig
}

type GitleaksConfig struct {
	// Config is a path to a gitleaks TOML config (custom rules, allowlists).
	// When empty, gitleaks's built-in default ruleset is used.
	Config string
	// MaxTargetMegaBytes caps per-file size; 0 means no cap.
	MaxTargetMegaBytes int
	// IgnorePath points at a .gitleaksignore file.
	IgnorePath string
	// Baseline points at a gitleaks baseline JSON to subtract from results.
	Baseline string
}

type TrufflehogConfig struct {
	Binary string
	// Verify toggles trufflehog's --no-verification flag. Default false
	// (no outbound calls). Setting true breaks the no-egress posture.
	Verify bool
	// Config is a path to a trufflehog YAML config (custom detectors, etc).
	Config string
	// IncludeDetectors / ExcludeDetectors map directly to trufflehog's
	// --include-detectors / --exclude-detectors flags.
	IncludeDetectors []string
	ExcludeDetectors []string
	// ExtraArgs is an escape hatch for any flag we don't model.
	// Appended after the modeled flags, before the trailing source argument.
	ExtraArgs []string
}

type KingfisherConfig struct {
	Binary string
	// Rules is a path to a kingfisher rules file.
	Rules string
	// Confidence sets the minimum confidence ("low" | "medium" | "high").
	Confidence string
	// ExtraArgs is an escape hatch for any flag we don't model.
	ExtraArgs []string
}

type LLMConfig struct {
	Endpoint              string
	Model                 string
	MaxInflight           int
	QueueMax              int
	RequestTimeout        time.Duration
	Profile               string
	MaxFindingsPerRequest int
	ContextBudget         ContextBudgetConfig
	Profiles              map[string]LLMProfile
	// UseTools routes adjudication through the OpenAI tool-calling
	// path: atalaia sends the verdict shape as a function-calling
	// tool and parses tool_calls instead of message content. Default
	// true. Set false only for backends without a registered
	// tool-call parser (some hosted providers, certain Ollama /
	// llama.cpp builds, vLLM without `--tool-call-parser`); the
	// content-parsing fallback then takes over.
	UseTools bool
}

type ContextBudgetConfig struct {
	InputTokens         int
	OutputTokens        int
	FindingContextLines int
}

type LLMProfile struct {
	SystemTemplate string
	UserTemplate   string
	ResponseFormat string
}

type ObservabilityConfig struct {
	LogLevel    string
	MetricsAddr string
	Audit       AuditConfig
}

// AuditConfig is opt-in (default Enabled=false). When enabled, Atalaia
// appends one JSONL entry per /check request to Path. RevealMatches
// is the explicit opt-in to write raw matched values instead of
// preview-redacted strings — leave false unless the deployment has a
// real reason to log unredacted secrets.
type AuditConfig struct {
	Enabled       bool
	Path          string
	RevealMatches bool
}

type TailscaleConfig struct {
	Enabled    bool
	Hostname   string
	StateDir   string
	AuthKey    string
	ControlURL string
	Ephemeral  bool
	ListenOnly bool
}

type LogConfig struct {
	Format     string
	Level      zerolog.Level
	WithCaller bool
}

// ReadViperConfig prepares and loads the Atalaia configuration into Viper.
// It sets defaults, reads the configuration file and environment variables.
// The configuration is not validated; the caller should invoke GetConfig
// to obtain a validated *Config.
// Stolen from Headscale :)
func ReadViperConfig(path string, isFile bool) error {
	log.Debug().Msg("Reading config")
	if isFile {
		viper.SetConfigFile(path)
	} else {
		viper.SetConfigName("atalaia")
		if path == "" {
			viper.AddConfigPath("/etc/atalaia/")
			viper.AddConfigPath("$HOME/.atalaia")
			viper.AddConfigPath(".")
		} else {
			viper.AddConfigPath(path)
		}
	}

	viper.SetEnvPrefix("atalaia")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	setDefaults()

	if err := viper.ReadInConfig(); err != nil {
		return err
	}
	return nil
}

func setDefaults() {
	// server
	viper.SetDefault("server.listen", "0.0.0.0:8080")
	viper.SetDefault("server.read_timeout", "30s")
	viper.SetDefault("server.write_timeout", "120s")
	viper.SetDefault("server.idle_timeout", "120s")
	viper.SetDefault("server.max_body_bytes", int64(10*1024*1024))

	// detectors
	viper.SetDefault("detectors.enabled", []string{"gitleaks", "trufflehog"})
	viper.SetDefault("detectors.parallel_timeout", "10s")
	viper.SetDefault("detectors.trufflehog.binary", "trufflehog")
	viper.SetDefault("detectors.trufflehog.verify", false)
	viper.SetDefault("detectors.kingfisher.binary", "kingfisher")

	// llm
	viper.SetDefault("llm.max_inflight", 1)
	viper.SetDefault("llm.queue_max", 16)
	viper.SetDefault("llm.request_timeout", "90s")
	viper.SetDefault("llm.profile", "gemma4")
	viper.SetDefault("llm.max_findings_per_request", 200)
	viper.SetDefault("llm.context_budget.input_tokens", 80000)
	viper.SetDefault("llm.context_budget.output_tokens", 8000)
	viper.SetDefault("llm.context_budget.finding_context_lines", 30)
	viper.SetDefault("llm.use_tools", true)

	// observability
	viper.SetDefault("observability.log_level", "info")
	viper.SetDefault("observability.metrics_addr", "0.0.0.0:9090")

	// tailscale
	viper.SetDefault("tailscale.enabled", false)
	viper.SetDefault("tailscale.hostname", "atalaia")
	viper.SetDefault("tailscale.state_dir", "/var/lib/atalaia/tsnet")
	viper.SetDefault("tailscale.ephemeral", false)
	viper.SetDefault("tailscale.listen_only", true)

	// log (compat with the existing block)
	viper.SetDefault("log.level", "info")
	viper.SetDefault("log.format", TextLogFormat)
	viper.SetDefault("log.with_caller", false)
}

// GetConfig assembles a *Config from the values already loaded by
// ReadViperConfig, applies the logging side effects (global level), and
// validates required fields.
func GetConfig() (*Config, error) {
	log.Debug().Msg("Creating config struct")

	cfg := &Config{
		Server:        readServerConfig(),
		Detectors:     readDetectorsConfig(),
		LLM:           readLLMConfig(),
		Observability: readObservabilityConfig(),
		Tailscale:     readTailscaleConfig(),
		Log:           readLogConfig(),
	}

	zerolog.SetGlobalLevel(cfg.Log.Level)

	if err := validateConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func readServerConfig() ServerConfig {
	return ServerConfig{
		Listen:       viper.GetString("server.listen"),
		ReadTimeout:  viper.GetDuration("server.read_timeout"),
		WriteTimeout: viper.GetDuration("server.write_timeout"),
		IdleTimeout:  viper.GetDuration("server.idle_timeout"),
		MaxBodyBytes: viper.GetInt64("server.max_body_bytes"),
		AuthToken:    viper.GetString("server.auth_token"),
	}
}

func readDetectorsConfig() DetectorsConfig {
	return DetectorsConfig{
		Enabled:         viper.GetStringSlice("detectors.enabled"),
		ParallelTimeout: viper.GetDuration("detectors.parallel_timeout"),
		Gitleaks: GitleaksConfig{
			Config:             viper.GetString("detectors.gitleaks.config"),
			MaxTargetMegaBytes: viper.GetInt("detectors.gitleaks.max_target_megabytes"),
			IgnorePath:         viper.GetString("detectors.gitleaks.ignore_path"),
			Baseline:           viper.GetString("detectors.gitleaks.baseline"),
		},
		Trufflehog: TrufflehogConfig{
			Binary:           viper.GetString("detectors.trufflehog.binary"),
			Verify:           viper.GetBool("detectors.trufflehog.verify"),
			Config:           viper.GetString("detectors.trufflehog.config"),
			IncludeDetectors: viper.GetStringSlice("detectors.trufflehog.include_detectors"),
			ExcludeDetectors: viper.GetStringSlice("detectors.trufflehog.exclude_detectors"),
			ExtraArgs:        viper.GetStringSlice("detectors.trufflehog.extra_args"),
		},
		Kingfisher: KingfisherConfig{
			Binary:     viper.GetString("detectors.kingfisher.binary"),
			Rules:      viper.GetString("detectors.kingfisher.rules"),
			Confidence: viper.GetString("detectors.kingfisher.confidence"),
			ExtraArgs:  viper.GetStringSlice("detectors.kingfisher.extra_args"),
		},
	}
}

func readLLMConfig() LLMConfig {
	c := LLMConfig{
		Endpoint:              viper.GetString("llm.endpoint"),
		Model:                 viper.GetString("llm.model"),
		MaxInflight:           viper.GetInt("llm.max_inflight"),
		QueueMax:              viper.GetInt("llm.queue_max"),
		RequestTimeout:        viper.GetDuration("llm.request_timeout"),
		Profile:               viper.GetString("llm.profile"),
		MaxFindingsPerRequest: viper.GetInt("llm.max_findings_per_request"),
		ContextBudget: ContextBudgetConfig{
			InputTokens:         viper.GetInt("llm.context_budget.input_tokens"),
			OutputTokens:        viper.GetInt("llm.context_budget.output_tokens"),
			FindingContextLines: viper.GetInt("llm.context_budget.finding_context_lines"),
		},
		Profiles: map[string]LLMProfile{},
		UseTools: viper.GetBool("llm.use_tools"),
	}

	raw := viper.GetStringMap("llm.profiles")
	for name := range raw {
		base := "llm.profiles." + name + "."
		c.Profiles[name] = LLMProfile{
			SystemTemplate: viper.GetString(base + "system_template"),
			UserTemplate:   viper.GetString(base + "user_template"),
			ResponseFormat: viper.GetString(base + "response_format"),
		}
	}
	return c
}

func readObservabilityConfig() ObservabilityConfig {
	return ObservabilityConfig{
		LogLevel:    viper.GetString("observability.log_level"),
		MetricsAddr: viper.GetString("observability.metrics_addr"),
		Audit: AuditConfig{
			Enabled:       viper.GetBool("observability.audit.enabled"),
			Path:          viper.GetString("observability.audit.path"),
			RevealMatches: viper.GetBool("observability.audit.reveal_matches"),
		},
	}
}

func readTailscaleConfig() TailscaleConfig {
	return TailscaleConfig{
		Enabled:    viper.GetBool("tailscale.enabled"),
		Hostname:   viper.GetString("tailscale.hostname"),
		StateDir:   viper.GetString("tailscale.state_dir"),
		AuthKey:    viper.GetString("tailscale.auth_key"),
		ControlURL: viper.GetString("tailscale.control_url"),
		Ephemeral:  viper.GetBool("tailscale.ephemeral"),
		ListenOnly: viper.GetBool("tailscale.listen_only"),
	}
}

func readLogConfig() LogConfig {
	levelStr := viper.GetString("log.level")
	level, err := zerolog.ParseLevel(levelStr)
	if err != nil {
		level = zerolog.InfoLevel
	}

	formatOpt := viper.GetString("log.format")
	format := TextLogFormat
	switch formatOpt {
	case JSONLogFormat:
		format = JSONLogFormat
	case TextLogFormat, "":
		format = TextLogFormat
	default:
		log.Error().Msgf("Could not parse log format: %s. Valid choices are 'json' or 'text'", formatOpt)
	}

	return LogConfig{
		Format:     format,
		Level:      level,
		WithCaller: viper.GetBool("log.with_caller"),
	}
}

// validateConfig checks required fields and enabled-detector preconditions.
// It is intentionally strict: an enabled subprocess detector whose binary
// cannot be resolved on $PATH (or at the configured absolute path) is a
// configuration error, since the running service would fail to scan.
func validateConfig(cfg *Config) error {
	var errs []string

	if cfg.Server.Listen == "" {
		errs = append(errs, "server.listen is required")
	}
	if cfg.LLM.Endpoint == "" {
		errs = append(errs, "llm.endpoint is required")
	}
	if cfg.LLM.Model == "" {
		errs = append(errs, "llm.model is required")
	}
	if cfg.LLM.MaxInflight < 1 {
		errs = append(errs, "llm.max_inflight must be >= 1")
	}
	if cfg.LLM.QueueMax < 0 {
		errs = append(errs, "llm.queue_max must be >= 0")
	}

	for _, name := range cfg.Detectors.Enabled {
		switch name {
		case "gitleaks":
			// in-process library; nothing to check on disk
		case "trufflehog":
			if err := checkBinary(cfg.Detectors.Trufflehog.Binary); err != nil {
				errs = append(errs, fmt.Sprintf("detectors.trufflehog.binary: %v", err))
			}
		case "kingfisher":
			if err := checkBinary(cfg.Detectors.Kingfisher.Binary); err != nil {
				errs = append(errs, fmt.Sprintf("detectors.kingfisher.binary: %v", err))
			}
		default:
			errs = append(errs, fmt.Sprintf("detectors.enabled: unknown detector %q", name))
		}
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

// ValidateAuthKeyNotInFile rejects YAML files that embed
// `tailscale.auth_key` as a literal value. The design requires the
// auth key to come from the environment (ATALAIA_TAILSCALE_AUTH_KEY)
// only — keys in config files leak into version control and backups.
// path may be empty (no file) in which case this is a no-op.
func ValidateAuthKeyNotInFile(path string) error {
	if path == "" {
		return nil
	}
	body, err := os.ReadFile(path)
	if err != nil {
		// Loading the file is the caller's job; only check when readable.
		return nil
	}
	var shape struct {
		Tailscale struct {
			AuthKey string `yaml:"auth_key"`
		} `yaml:"tailscale"`
	}
	if err := yaml.Unmarshal(body, &shape); err != nil {
		return nil // syntax errors surface via the real loader
	}
	if strings.TrimSpace(shape.Tailscale.AuthKey) != "" {
		return fmt.Errorf("tailscale.auth_key must come from the environment (ATALAIA_TAILSCALE_AUTH_KEY); not from %q", path)
	}
	return nil
}

func checkBinary(path string) error {
	if path == "" {
		return errors.New("binary path is empty")
	}
	if _, err := exec.LookPath(path); err != nil {
		return fmt.Errorf("not found on PATH or at %q: %w", path, err)
	}
	return nil
}
