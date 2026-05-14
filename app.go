package atalaia

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/juanfont/atalaia/internal/api"
	"github.com/juanfont/atalaia/internal/audit"
	"github.com/juanfont/atalaia/internal/detector"
	"github.com/juanfont/atalaia/internal/llm"
	"github.com/juanfont/atalaia/internal/types"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"tailscale.com/tsnet"
)

// Version is overridden via -ldflags at build time. The CLI's `version`
// subcommand and the `/version` handler both read this value.
var Version = "dev"

type App struct {
	config        *types.Config
	mainServer    *http.Server
	hostServer    *http.Server // optional host listener when tsnet is enabled but not listen_only
	metricsServer *http.Server
	tsnetServer   *tsnet.Server
	audit         audit.Writer
}

func NewAtalaiaApp(config *types.Config) *App {
	return &App{config: config}
}

func (a *App) Shutdown(ctx context.Context) error {
	var firstErr error
	track := func(err error, msg string) {
		if err != nil {
			log.Error().Err(err).Msg(msg)
			if firstErr == nil {
				firstErr = err
			}
		}
	}

	if a.mainServer != nil {
		log.Info().Msg("Shutting down main HTTP server")
		track(a.mainServer.Shutdown(ctx), "main HTTP shutdown")
	}
	if a.hostServer != nil {
		track(a.hostServer.Shutdown(ctx), "host listener shutdown")
	}
	if a.metricsServer != nil {
		track(a.metricsServer.Shutdown(ctx), "metrics HTTP shutdown")
	}
	if a.tsnetServer != nil {
		track(a.tsnetServer.Close(), "tsnet close")
	}
	if a.audit != nil {
		track(a.audit.Close(), "audit close")
	}
	return firstErr
}

// Close is a convenience method that calls Shutdown with a default timeout.
func (a *App) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return a.Shutdown(ctx)
}

func (a *App) Serve() error {
	dets, err := detector.BuildEnabled(a.config.Detectors)
	if err != nil {
		return err
	}

	llmClient := llm.NewClient(a.config.LLM.Endpoint, a.config.LLM.Model, a.config.LLM.RequestTimeout)
	adjudicator, err := llm.NewAdjudicator(a.config.LLM, llmClient)
	if err != nil {
		return err
	}

	auditWriter, err := audit.New(a.config.Observability.Audit)
	if err != nil {
		return err
	}
	a.audit = auditWriter

	mainRouter := mux.NewRouter()
	if _, err := api.NewApp(context.Background(), api.Deps{
		Config:      a.config,
		Detectors:   dets,
		Adjudicator: adjudicator,
		Audit:       auditWriter,
		Version:     Version,
		Router:      mainRouter,
	}); err != nil {
		return err
	}

	a.mainServer = &http.Server{
		Handler:      mainRouter,
		ReadTimeout:  a.config.Server.ReadTimeout,
		WriteTimeout: a.config.Server.WriteTimeout,
	}

	// Metrics listener stays on the host network — scraping should
	// never traverse the tailnet even when /check does.
	if addr := a.config.Observability.MetricsAddr; addr != "" {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.Handler())
		a.metricsServer = &http.Server{Addr: addr, Handler: metricsMux}
		go func() {
			log.Info().Str("addr", addr).Msg("Atalaia metrics listener")
			if err := a.metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error().Err(err).Msg("metrics listener crashed")
			}
		}()
	}

	mainListener, err := a.buildMainListener()
	if err != nil {
		return err
	}

	log.Info().Str("addr", mainListenerAddr(mainListener)).Bool("tsnet", a.tsnetServer != nil).Msg("Atalaia HTTP server listening")
	if err := a.mainServer.Serve(mainListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// buildMainListener returns the net.Listener the main router serves on.
// When tailscale is enabled, the listener is the tsnet listener (and
// optionally an additional host listener bound concurrently). When
// disabled, it's a plain host listener.
func (a *App) buildMainListener() (net.Listener, error) {
	ts := a.config.Tailscale
	if !ts.Enabled {
		return net.Listen("tcp", a.config.Server.Listen)
	}

	authKey := ts.AuthKey // resolved from ATALAIA_TAILSCALE_AUTH_KEY by viper
	if authKey == "" {
		return nil, fmt.Errorf("tailscale.enabled but ATALAIA_TAILSCALE_AUTH_KEY is not set")
	}

	a.tsnetServer = &tsnet.Server{
		Hostname:   ts.Hostname,
		Dir:        ts.StateDir,
		AuthKey:    authKey,
		ControlURL: ts.ControlURL,
		Ephemeral:  ts.Ephemeral,
	}
	if err := a.tsnetServer.Start(); err != nil {
		return nil, fmt.Errorf("tsnet start: %w", err)
	}

	tailnetListener, err := a.tsnetServer.Listen("tcp", listenPort(a.config.Server.Listen))
	if err != nil {
		return nil, fmt.Errorf("tsnet listen: %w", err)
	}

	if ts.ListenOnly {
		return tailnetListener, nil
	}

	// Bind a host listener alongside the tailnet listener. Use a
	// dedicated *http.Server so Shutdown can stop it independently.
	hostListener, err := net.Listen("tcp", a.config.Server.Listen)
	if err != nil {
		tailnetListener.Close()
		return nil, fmt.Errorf("host listen: %w", err)
	}
	a.hostServer = &http.Server{
		Handler:      a.mainServer.Handler,
		ReadTimeout:  a.mainServer.ReadTimeout,
		WriteTimeout: a.mainServer.WriteTimeout,
	}
	go func() {
		log.Info().Str("addr", a.config.Server.Listen).Msg("Atalaia host listener (alongside tsnet)")
		if err := a.hostServer.Serve(hostListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error().Err(err).Msg("host listener crashed")
		}
	}()
	return tailnetListener, nil
}

// listenPort extracts ":port" from "host:port"; tsnet's Listen ignores
// the host portion and binds to the tailnet address, but the port has
// to come from somewhere.
func listenPort(listen string) string {
	if _, port, err := net.SplitHostPort(listen); err == nil {
		return ":" + port
	}
	return listen
}

func mainListenerAddr(l net.Listener) string {
	if l == nil {
		return ""
	}
	return l.Addr().String()
}
