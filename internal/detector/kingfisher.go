package detector

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"

	"github.com/juanfont/atalaia/internal/types"
)

// Kingfisher is the subprocess adapter for mongodb/kingfisher. Disabled
// by default in atalaia.yaml; opt in by adding "kingfisher" to
// detectors.enabled.
//
// The exact stdin/output flag shape is verified at integration time;
// the structural pieces here mirror the trufflehog adapter (subprocess
// + JSONL parse + locate-in-diff fallback) so they can be tuned in one
// place when the binary is pinned.
type Kingfisher struct {
	cfg types.KingfisherConfig
}

func NewKingfisher(cfg types.KingfisherConfig) *Kingfisher {
	return &Kingfisher{cfg: cfg}
}

func (k *Kingfisher) Name() string { return "kingfisher" }

type kingfisherResult struct {
	Rule     string `json:"rule"`
	RuleName string `json:"rule_name"`
	Match    string `json:"match"`
	Secret   string `json:"secret"`
	Path     string `json:"path"`
	Line     int    `json:"line"`
	Verified bool   `json:"verified"`
}

func (k *Kingfisher) Scan(ctx context.Context, diff []byte) ([]Finding, error) {
	bin := k.cfg.Binary
	if bin == "" {
		bin = "kingfisher"
	}

	args := []string{"scan", "--format", "json", "--stdin"}
	if k.cfg.Rules != "" {
		args = append(args, "--rules", k.cfg.Rules)
	}
	if k.cfg.Confidence != "" {
		args = append(args, "--confidence", k.cfg.Confidence)
	}
	args = append(args, k.cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(diff)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("kingfisher: stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("kingfisher: start %q: %w", bin, err)
	}

	findings := parseKingfisherStream(stdout, diff)

	if err := cmd.Wait(); err != nil {
		if len(findings) == 0 {
			return nil, fmt.Errorf("kingfisher: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
	}
	return findings, nil
}

func parseKingfisherStream(r io.Reader, diff []byte) []Finding {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var res kingfisherResult
		if err := json.Unmarshal(line, &res); err != nil {
			continue
		}
		match := res.Secret
		if match == "" {
			match = res.Match
		}
		if match == "" {
			continue
		}
		file, lineNum := res.Path, res.Line
		if file == "" || lineNum == 0 {
			file, lineNum = locateInDiff(diff, match)
		}
		name := res.RuleName
		if name == "" {
			name = res.Rule
		}
		out = append(out, Finding{
			DetectorType: "kingfisher",
			DetectorName: name,
			Rule:         res.Rule,
			File:         file,
			Line:         lineNum,
			Match:        match,
			Verified:     res.Verified,
		})
	}
	return out
}
