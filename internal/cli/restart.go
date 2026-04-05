package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newRestartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "restart <plugin>",
		Short: "Restart a plugin container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			// Stop existing container if running
			if p.State == plugin.StateRunning && p.ContainerID != "" {
				fmt.Printf("Stopping plugin %q...\n", name)
				if err := app.Runtime.Stop(ctx, p.ContainerID, 10*time.Second); err != nil {
					slog.Warn("error stopping container", "error", err)
				}
				_ = app.Runtime.Remove(ctx, p.ContainerID)
			}

			return startPlugin(ctx, p)
		},
	}
}
