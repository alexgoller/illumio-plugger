package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/illumio/plugger/internal/config"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize the plugger configuration directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir := config.DefaultDataDir()

			// Create data directory
			if err := os.MkdirAll(dataDir, 0700); err != nil {
				return fmt.Errorf("creating data directory: %w", err)
			}
			fmt.Printf("Created %s\n", dataDir)

			// Create plugins directory
			pluginsDir := filepath.Join(dataDir, "plugins")
			if err := os.MkdirAll(pluginsDir, 0700); err != nil {
				return fmt.Errorf("creating plugins directory: %w", err)
			}

			// Write default config if it doesn't exist
			cfgPath := filepath.Join(dataDir, "config.yaml")
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				if err := config.WriteDefault(cfgPath); err != nil {
					return fmt.Errorf("writing default config: %w", err)
				}
				fmt.Printf("Created %s\n", cfgPath)
			} else {
				fmt.Printf("Config already exists at %s\n", cfgPath)
			}

			fmt.Println("\nEdit the config file to set your PCE connection details, then run:")
			fmt.Println("  plugger install <manifest.yaml>")
			return nil
		},
	}
}
