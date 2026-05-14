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

// Deps bundles everything the API layer needs from the lifecycle owner.
// Keeping this in one struct keeps the call site readable as the dep
// list grows (LLM client lands in milestone 4).
type Deps struct {
	Config      *types.Config
	Detectors   []detector.Detector
	Adjudicator Adjudicator
	Audit       audit.Writer
	Version     string
	Router      *mux.Router
}

type App struct {
	config      *types.Config
	detectors   []detector.Detector
	adjudicator Adjudicator
	audit       audit.Writer
	version     string
	logger      zerolog.Logger
}

// NewApp registers the API handlers on the shared router. The LLM
// client and observability hooks are folded in by later milestones;
// the signature is intentionally stable across them.
func NewApp(_ context.Context, d Deps) (*App, error) {
	auditWriter := d.Audit
	if auditWriter == nil {
		auditWriter = audit.Nop()
	}
	app := &App{
		config:      d.Config,
		detectors:   d.Detectors,
		adjudicator: d.Adjudicator,
		audit:       auditWriter,
		version:     d.Version,
		logger:      log.Logger,
	}
	d.Router.HandleFunc("/check", app.Check).Methods("POST")
	d.Router.HandleFunc("/healthz", app.Healthz).Methods("GET")
	d.Router.HandleFunc("/version", app.Version).Methods("GET")
	return app, nil
}
