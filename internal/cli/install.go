package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	var envOverrides []string

	cmd := &cobra.Command{
		Use:   "install <manifest.yaml>",
		Short: "Install a plugin from a manifest file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestPath := args[0]

			manifest, err := config.LoadManifest(manifestPath)
			if err != nil {
				return err
			}

			// Check if already installed
			if existing, _ := app.Store.Get(manifest.Name); existing != nil {
				return fmt.Errorf("plugin %q is already installed (use uninstall first)", manifest.Name)
			}

			// Pull image
			fmt.Printf("Pulling image %s...\n", manifest.Image)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			if err := app.Runtime.Pull(ctx, manifest.Image); err != nil {
				return fmt.Errorf("pulling image: %w", err)
			}

			// Parse env overrides
			overrides := parseEnvOverrides(envOverrides)

			// Validate required env vars are provided
			for _, e := range manifest.Env {
				if e.Required && e.Default == "" {
					if _, ok := overrides[e.Name]; !ok {
						return fmt.Errorf("required env var %s not provided (use --env %s=VALUE)", e.Name, e.Name)
					}
				}
			}

			// Save plugin
			p := &plugin.Plugin{
				Name:         manifest.Name,
				Manifest:     *manifest,
				State:        plugin.StateInstalled,
				Enabled:      true,
				EnvOverrides: overrides,
				InstalledAt:  time.Now(),
			}

			if err := app.Store.Put(p); err != nil {
				return fmt.Errorf("saving plugin: %w", err)
			}

			slog.Info("plugin installed", "name", manifest.Name, "image", manifest.Image, "mode", manifest.Schedule.Mode)
			fmt.Printf("Installed plugin %q (%s, mode=%s)\n", manifest.Name, manifest.Version, manifest.Schedule.Mode)
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&envOverrides, "env", "e", nil, "environment variable overrides (KEY=VALUE)")
	return cmd
}

func parseEnvOverrides(pairs []string) map[string]string {
	result := make(map[string]string)
	for _, pair := range pairs {
		for i := 0; i < len(pair); i++ {
			if pair[i] == '=' {
				result[pair[:i]] = pair[i+1:]
				break
			}
		}
	}
	return result
}
