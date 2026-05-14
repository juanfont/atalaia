// Package audit writes one structured entry per /check request to an
// opt-in JSONL sink. Raw matched values are written **only** when
// AuditConfig.RevealMatches is true; otherwise entries carry only the
// already-redacted match_preview.
//
// The audit log is the single sanctioned channel for unredacted match
// content in Atalaia. Application logs and the /check response are
// preview-only by contract.
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/juanfont/atalaia/internal/types"
)

// Verdict is the per-finding shape inside an Entry. Match is empty
// unless RevealMatches is true on the configured AuditConfig.
type Verdict struct {
	ID           string  `json:"id"`
	File         string  `json:"file"`
	Line         int     `json:"line"`
	MatchPreview string  `json:"match_preview"`
	Match        string  `json:"match,omitempty"`
	Verdict      string  `json:"verdict"`
	Confidence   float64 `json:"confidence"`
	Reason       string  `json:"reason"`
}

// Entry is one JSONL record per /check call.
type Entry struct {
	Timestamp    string    `json:"timestamp"`
	RequestID    string    `json:"request_id"`
	RemoteAddr   string    `json:"remote_addr,omitempty"`
	DiffBytes    int       `json:"diff_bytes"`
	DetectorsRun []string  `json:"detectors_run"`
	RawFindings  int       `json:"raw_findings"`
	AfterDedup   int       `json:"after_dedup"`
	Confirmed    int       `json:"confirmed"`
	Dismissed    int       `json:"dismissed"`
	LLMInvoked   bool      `json:"llm_invoked"`
	LLMCalls     int       `json:"llm_calls"`
	LLMModel     string    `json:"llm_model"`
	LLMLatencyMs int64     `json:"llm_latency_ms"`
	TotalMs      int64     `json:"total_latency_ms"`
	Truncated    bool      `json:"truncated"`
	Verdicts     []Verdict `json:"verdicts"`
}

// Writer is the audit-log sink. Real deployments use *FileWriter;
// when audit is disabled the API layer uses Nop().
type Writer interface {
	Write(entry Entry) error
	io.Closer
}

// Nop returns a Writer that drops every entry. Used when
// observability.audit.enabled is false.
func Nop() Writer { return nopWriter{} }

type nopWriter struct{}

func (nopWriter) Write(Entry) error { return nil }
func (nopWriter) Close() error      { return nil }

// FileWriter is a JSONL append-only sink. Each Write is serialized
// under a mutex; we trade fan-out for the guarantee that one Entry =
// one line.
type FileWriter struct {
	mu      sync.Mutex
	f       *os.File
	encoder *json.Encoder
}

// NewFileWriter opens (or creates) path for append. The caller is
// responsible for Close at process shutdown.
func NewFileWriter(path string) (*FileWriter, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open audit log %q: %w", path, err)
	}
	return &FileWriter{f: f, encoder: json.NewEncoder(f)}, nil
}

func (w *FileWriter) Write(entry Entry) error {
	if entry.Timestamp == "" {
		entry.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.encoder.Encode(entry)
}

func (w *FileWriter) Close() error { return w.f.Close() }

// New returns the appropriate Writer for cfg. Disabled config gets
// Nop(); enabled-but-blank-path is an error.
func New(cfg types.AuditConfig) (Writer, error) {
	if !cfg.Enabled {
		return Nop(), nil
	}
	if cfg.Path == "" {
		return nil, fmt.Errorf("audit log enabled but observability.audit.path is empty")
	}
	return NewFileWriter(cfg.Path)
}
