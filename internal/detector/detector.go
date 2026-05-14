package detector

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Finding is the canonical, detector-agnostic shape that every adapter
// emits. The (File, Line, Match) triple is the dedup key; FindingID
// hashes that triple and is the correlation key used across the API
// response and the LLM prompt.
type Finding struct {
	DetectorType string
	DetectorName string
	Rule         string
	File         string
	Line         int
	Match        string
	Verified     bool
}

// Detector is the contract every secret-scanner adapter implements.
type Detector interface {
	Name() string
	Scan(ctx context.Context, diff []byte) ([]Finding, error)
}

// FindingID returns the stable 12-hex-char ID for a (file, line, match)
// triple. Same triple across re-runs yields the same ID; opaque enough
// not to leak the match value.
func FindingID(f Finding) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", f.File, f.Line, f.Match)))
	return hex.EncodeToString(h[:])[:12]
}
