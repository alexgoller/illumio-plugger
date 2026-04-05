package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newUninstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "uninstall <plugin>",
		Short: "Uninstall a plugin and remove its container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Stop and remove container if running
			if p.State == plugin.StateRunning || p.ContainerID != "" {
				fmt.Printf("Stopping container %s...\n", p.ContainerName())
				if err := app.Runtime.Stop(ctx, p.ContainerID, 10*time.Second); err != nil {
					slog.Warn("failed to stop container", "error", err)
				}
				if err := app.Runtime.Remove(ctx, p.ContainerID); err != nil {
					slog.Warn("failed to remove container", "error", err)
				}
			}

			if err := app.Store.Delete(name); err != nil {
				return fmt.Errorf("removing plugin: %w", err)
			}

			fmt.Printf("Uninstalled plugin %q\n", name)
			return nil
		},
	}
}
