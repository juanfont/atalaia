package api

import (
	"context"

	"github.com/gorilla/mux"
	"github.com/juanfont/atalaia/internal/audit"
	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/llm"
	"github.com/juanfont/atalaia/internal/types"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Adjudicator is the seam between the API layer and internal/llm.
// *llm.Adjudicator implements it; tests substitute a fake.
type Adjudicator interface {
	Adjudicate(ctx context.Context, diff []byte, deduped []detector.DedupedFinding) (llm.AdjudicateResult, error)
	Probe(ctx context.Context) error
}

// Reachability is the seam for /readyz. *llm.ReachabilityWatcher
// implements it by polling the LLM in the background; tests fake it.
// Returns true when the last cached probe was both successful and
// recent.
type Reachability interface {
	Ready() bool
}

// Deps bundles everything the API layer needs from the lifecycle owner.
// Keeping this in one struct keeps the call site readable as the dep
// list grows (LLM client lands in milestone 4).
type Deps struct {
	Config       *types.Config
	Detectors    []detector.Detector
	Adjudicator  Adjudicator
	Reachability Reachability
	Audit        audit.Writer
	Version      string
	Router       *mux.Router
}

type App struct {
	config       *types.Config
	detectors    []detector.Detector
	detectSem    chan struct{} // bounds concurrent detector scans; nil = unbounded
	adjudicator  Adjudicator
	reachability Reachability
	audit        audit.Writer
	version      string
	logger       zerolog.Logger
}

// NewApp registers the API handlers on the shared router. The LLM
// client and observability hooks are folded in by later milestones;
// the signature is intentionally stable across them.
func NewApp(_ context.Context, d Deps) (*App, error) {
	auditWriter := d.Audit
	if auditWriter == nil {
		auditWriter = audit.Nop()
	}
	var detectSem chan struct{}
	if n := d.Config.Detectors.MaxConcurrentScans; n > 0 {
		detectSem = make(chan struct{}, n)
	}
	app := &App{
		config:       d.Config,
		detectors:    d.Detectors,
		detectSem:    detectSem,
		adjudicator:  d.Adjudicator,
		reachability: d.Reachability,
		audit:        auditWriter,
		version:      d.Version,
		logger:       log.Logger,
	}
	d.Router.HandleFunc("/check", bearerAuth(d.Config.Server.AuthToken, app.Check)).Methods("POST")
	d.Router.HandleFunc("/healthz", app.Healthz).Methods("GET")
	d.Router.HandleFunc("/readyz", app.Readyz).Methods("GET")
	d.Router.HandleFunc("/version", app.Version).Methods("GET")
	return app, nil
}
