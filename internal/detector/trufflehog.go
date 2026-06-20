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

// Trufflehog is the subprocess adapter for trufflesecurity/trufflehog.
//
// Trufflehog is AGPL-3.0 and is therefore invoked as a subprocess so
// Atalaia can stay BSD-3-Clause. Never import it as a Go module.
type Trufflehog struct {
	cfg types.TrufflehogConfig
}

func NewTrufflehog(cfg types.TrufflehogConfig) *Trufflehog {
	return &Trufflehog{cfg: cfg}
}

func (t *Trufflehog) Name() string { return "trufflehog" }

// trufflehogResult mirrors the fields we consume from each JSONL line.
// Trufflehog emits many more fields; we keep this shape narrow.
type trufflehogResult struct {
	DetectorName        string `json:"DetectorName"`
	DetectorDescription string `json:"DetectorDescription"`
	Verified            bool   `json:"Verified"`
	Raw                 string `json:"Raw"`
	RawV2               string `json:"RawV2"`
	SourceMetadata      struct {
		Data map[string]json.RawMessage `json:"Data"`
	} `json:"SourceMetadata"`
}

func (t *Trufflehog) Scan(ctx context.Context, diff []byte) ([]Finding, error) {
	bin := t.cfg.Binary
	if bin == "" {
		bin = "trufflehog"
	}

	// --no-update suppresses trufflehog's self-update check, which
	// fails (and exits 1) whenever the binary isn't writable — CI
	// runners, containers, and any non-root install path.
	args := []string{"stdin", "--json", "--no-update"}
	if !t.cfg.Verify {
		args = append(args, "--no-verification")
	}
	if t.cfg.Config != "" {
		args = append(args, "--config", t.cfg.Config)
	}
	for _, d := range t.cfg.IncludeDetectors {
		args = append(args, "--include-detectors", d)
	}
	for _, d := range t.cfg.ExcludeDetectors {
		args = append(args, "--exclude-detectors", d)
	}
	args = append(args, t.cfg.ExtraArgs...)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(diff)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("trufflehog: stdout pipe: %w", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("trufflehog: start %q: %w", bin, err)
	}

	findings := parseTrufflehogStream(stdout, diff)

	if err := cmd.Wait(); err != nil {
		// Trufflehog exits non-zero when it finds secrets in some
		// builds; treat findings as authoritative when we got any.
		if len(findings) == 0 {
			return nil, fmt.Errorf("trufflehog: %w (stderr: %s)", err, strings.TrimSpace(stderr.String()))
		}
	}
	return findings, nil
}

// parseTrufflehogStream reads JSONL from r and returns canonical
// findings. file/line metadata is derived by searching the diff for
// the Raw match value, since `trufflehog stdin` does not preserve
// source positions.
func parseTrufflehogStream(r io.Reader, diff []byte) []Finding {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 || line[0] != '{' {
			continue
		}
		var res trufflehogResult
		if err := json.Unmarshal(line, &res); err != nil {
			continue
		}
		match := res.Raw
		if match == "" {
			match = res.RawV2
		}
		if match == "" {
			continue
		}
		file, lineNum := locateInDiff(diff, match)
		out = append(out, Finding{
			DetectorType: "trufflehog",
			DetectorName: res.DetectorName,
			Rule:         res.DetectorName,
			File:         file,
			Line:         lineNum,
			Match:        match,
			Verified:     res.Verified,
		})
	}
	return out
}
