package cli

import (
	"fmt"

	"github.com/juanfont/atalaia"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version, configured LLM model, and detector versions",
	Run: func(_ *cobra.Command, _ []string) {
		fmt.Printf("atalaia      %s\n", atalaia.Version)

		llmModel := "unknown"
		if cfg, err := loadConfig(); err == nil {
			llmModel = cfg.LLM.Model
		}
		fmt.Printf("llm.model    %s\n", llmModel)

		// Detector binaries don't yet expose a version accessor;
		// follow-up in milestone 6.
		fmt.Println("gitleaks     unknown")
		fmt.Println("trufflehog   unknown")
		fmt.Println("kingfisher   unknown")
	},
}
