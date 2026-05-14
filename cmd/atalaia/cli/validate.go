package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(validateCmd)
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Parse and validate the configuration",
	RunE: func(_ *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		fmt.Printf("config OK: listen=%s llm.endpoint=%s llm.model=%s detectors=%v\n",
			cfg.Server.Listen, cfg.LLM.Endpoint, cfg.LLM.Model, cfg.Detectors.Enabled)
		return nil
	},
}
