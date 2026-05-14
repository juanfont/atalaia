package cli

import (
	"context"
	"os/signal"
	"syscall"
	"time"

	"github.com/juanfont/atalaia"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Run the Atalaia HTTP service",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}

		app := atalaia.NewAtalaiaApp(cfg)

		ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
		defer stop()

		errCh := make(chan error, 1)
		go func() { errCh <- app.Serve() }()

		select {
		case <-ctx.Done():
			log.Info().Msg("Shutdown signal received")
		case err := <-errCh:
			return err
		}

		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return app.Shutdown(shutdownCtx)
	},
}
