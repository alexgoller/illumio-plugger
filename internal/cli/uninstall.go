package cli

import (
	"context"
	"fmt"
	"time"

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

			// Stop and remove container — try both name and ID
			fmt.Printf("Stopping container %s...\n", p.ContainerName())
			_ = app.Runtime.Stop(ctx, p.ContainerName(), 10*time.Second)
			_ = app.Runtime.Remove(ctx, p.ContainerName())
			if p.ContainerID != "" {
				_ = app.Runtime.Stop(ctx, p.ContainerID, 10*time.Second)
				_ = app.Runtime.Remove(ctx, p.ContainerID)
			}

			if err := app.Store.Delete(name); err != nil {
				return fmt.Errorf("removing plugin: %w", err)
			}

			fmt.Printf("Uninstalled plugin %q\n", name)
			return nil
		},
	}
}
