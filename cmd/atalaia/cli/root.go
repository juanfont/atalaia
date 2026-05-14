package cli

import (
	"fmt"
	"os"

	"github.com/juanfont/atalaia/internal/types"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var cfgFile string

func init() {
	rootCmd.PersistentFlags().
		StringVarP(&cfgFile, "config", "c", "", "config file (default is /etc/atalaia/atalaia.yaml)")
}

var rootCmd = &cobra.Command{
	Use:   "atalaia",
	Short: "Atalaia - A secret detection tool",
	Long: `Atalaia is a secret detection tool that receives POST requests with the content to be scanned and returns the results of the scan.

https://github.com/juanfont/atalaia`,
	SilenceUsage: true,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

// loadConfig reads the active config file (resolved from -c, the search
// path, or env vars) and returns a validated *Config. Subcommands that
// need configuration call this in their RunE; commands like `version`
// that must always work do not.
func loadConfig() (*types.Config, error) {
	if cfgFile != "" {
		if err := types.ValidateAuthKeyNotInFile(cfgFile); err != nil {
			return nil, err
		}
		if err := types.ReadViperConfig(cfgFile, true); err != nil {
			return nil, fmt.Errorf("loading config file %q: %w", cfgFile, err)
		}
	} else {
		if err := types.ReadViperConfig("", false); err != nil {
			return nil, fmt.Errorf("loading config: %w", err)
		}
		// When viper resolved the file via search-path, double-check it.
		if used := viper.ConfigFileUsed(); used != "" {
			if err := types.ValidateAuthKeyNotInFile(used); err != nil {
				return nil, err
			}
		}
	}

	if viper.GetString("log.format") == types.JSONLogFormat {
		log.Logger = log.Output(os.Stdout)
	}

	return types.GetConfig()
}
