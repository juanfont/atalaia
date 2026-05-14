package detector

import (
	"context"
	"fmt"

	"github.com/juanfont/atalaia/internal/types"
	"github.com/spf13/viper"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"github.com/zricethezav/gitleaks/v8/sources"
)

// Gitleaks is the in-process adapter for gitleaks. The license is MIT,
// so it can be imported as a Go library (unlike trufflehog).
type Gitleaks struct {
	detector *detect.Detector
}

// NewGitleaks loads the gitleaks default ruleset, optionally overlaying
// a user-supplied TOML config, and applies optional per-adapter knobs.
func NewGitleaks(cfg types.GitleaksConfig) (*Gitleaks, error) {
	det, err := buildGitleaksDetector(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.MaxTargetMegaBytes > 0 {
		det.MaxTargetMegaBytes = cfg.MaxTargetMegaBytes
	}
	if cfg.IgnorePath != "" {
		if err := det.AddGitleaksIgnore(cfg.IgnorePath); err != nil {
			return nil, fmt.Errorf("gitleaks: load ignore %q: %w", cfg.IgnorePath, err)
		}
	}
	if cfg.Baseline != "" {
		if err := det.AddBaseline(cfg.Baseline, ""); err != nil {
			return nil, fmt.Errorf("gitleaks: load baseline %q: %w", cfg.Baseline, err)
		}
	}
	return &Gitleaks{detector: det}, nil
}

func buildGitleaksDetector(cfg types.GitleaksConfig) (*detect.Detector, error) {
	if cfg.Config == "" {
		det, err := detect.NewDetectorDefaultConfig()
		if err != nil {
			return nil, fmt.Errorf("gitleaks: default config: %w", err)
		}
		return det, nil
	}

	// Use an isolated viper instance so we don't clobber the global
	// atalaia config viper that the rest of the binary relies on.
	v := viper.New()
	v.SetConfigFile(cfg.Config)
	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("gitleaks: read config %q: %w", cfg.Config, err)
	}
	var vc config.ViperConfig
	if err := v.Unmarshal(&vc); err != nil {
		return nil, fmt.Errorf("gitleaks: unmarshal config %q: %w", cfg.Config, err)
	}
	translated, err := vc.Translate()
	if err != nil {
		return nil, fmt.Errorf("gitleaks: translate config %q: %w", cfg.Config, err)
	}
	return detect.NewDetector(translated), nil
}

func (g *Gitleaks) Name() string { return "gitleaks" }

func (g *Gitleaks) Scan(ctx context.Context, diff []byte) ([]Finding, error) {
	blocks := WalkDiff(diff)
	var out []Finding
	for _, block := range blocks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fragment := sources.Fragment{
			Raw:       block.Content,
			FilePath:  block.Path,
			StartLine: block.StartLine,
		}
		for _, f := range g.detector.DetectContext(ctx, detect.Fragment(fragment)) {
			out = append(out, Finding{
				DetectorType: "gitleaks",
				DetectorName: f.RuleID,
				Rule:         f.RuleID,
				File:         f.File,
				Line:         f.StartLine,
				Match:        f.Secret,
				Verified:     false,
			})
		}
	}
	return out, nil
}
