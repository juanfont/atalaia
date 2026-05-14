package cli

import (
	"context"
	"fmt"

	"github.com/juanfont/atalaia/internal/llm"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(probeCmd)
}

var probeCmd = &cobra.Command{
	Use:   "probe",
	Short: "Issue a one-token completion to the configured LLM endpoint",
	RunE: func(cmd *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		client := llm.NewClient(cfg.LLM.Endpoint, cfg.LLM.Model, cfg.LLM.RequestTimeout)

		ctx := cmd.Context()
		if cfg.LLM.RequestTimeout > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, cfg.LLM.RequestTimeout)
			defer cancel()
		}
		if err := client.Probe(ctx); err != nil {
			return fmt.Errorf("probe %s: %w", cfg.LLM.Endpoint, err)
		}
		fmt.Printf("probe OK: %s @ %s\n", cfg.LLM.Model, cfg.LLM.Endpoint)
		return nil
	},
}
