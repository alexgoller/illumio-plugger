package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "upgrade <plugin>",
		Short: "Upgrade a plugin to the latest version from the registry",
		Long: `Pull the latest image for a plugin from the registry, stop the running
container, and restart with the new image.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return fmt.Errorf("plugin %q not installed", name)
			}

			// Find in registry
			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			regPlugin, err := mgr.FindPlugin(name)
			if err != nil {
				return err
			}

			fmt.Printf("Upgrading %s: %s → %s\n", name, p.Manifest.Version, regPlugin.Version)
			fmt.Printf("Image: %s\n", regPlugin.Image)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			// Pull new image
			fmt.Printf("Pulling %s...\n", regPlugin.Image)
			if err := app.Runtime.Pull(ctx, regPlugin.Image); err != nil {
				return fmt.Errorf("pulling image: %w", err)
			}

			// Update manifest with new image and version
			p.Manifest.Image = regPlugin.Image
			p.Manifest.Version = regPlugin.Version

			// Stop if running
			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}
			if p.State == plugin.StateRunning {
				fmt.Println("Stopping current version...")
				if err := lifecycle.StopPlugin(ctx, deps, p); err != nil {
					slog.Warn("error stopping", "error", err)
				}
			}

			// Save updated manifest
			if err := app.Store.Put(p); err != nil {
				return fmt.Errorf("saving plugin: %w", err)
			}

			// Restart
			fmt.Println("Starting new version...")
			if err := lifecycle.StartPlugin(ctx, deps, p); err != nil {
				return fmt.Errorf("starting: %w", err)
			}

			fmt.Printf("Upgraded %s to %s (container %s)\n", name, regPlugin.Version, p.ContainerID[:12])
			return nil
		},
	}
}
