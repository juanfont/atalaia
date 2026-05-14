package detector

import (
	"fmt"

	"github.com/juanfont/atalaia/internal/types"
)

// BuildEnabled constructs detector adapters for every name in
// cfg.Enabled. Order in the result mirrors cfg.Enabled order; an
// unknown name is a configuration error and short-circuits the build.
func BuildEnabled(cfg types.DetectorsConfig) ([]Detector, error) {
	out := make([]Detector, 0, len(cfg.Enabled))
	for _, name := range cfg.Enabled {
		switch name {
		case "gitleaks":
			g, err := NewGitleaks(cfg.Gitleaks)
			if err != nil {
				return nil, fmt.Errorf("build gitleaks: %w", err)
			}
			out = append(out, g)
		case "trufflehog":
			out = append(out, NewTrufflehog(cfg.Trufflehog))
		case "kingfisher":
			out = append(out, NewKingfisher(cfg.Kingfisher))
		default:
			return nil, fmt.Errorf("unknown detector %q", name)
		}
	}
	return out, nil
}
