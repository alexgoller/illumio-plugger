package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newStopCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "stop <plugin>",
		Short: "Stop a running plugin container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			if p.State != plugin.StateRunning {
				return fmt.Errorf("plugin %q is not running (state: %s)", name, p.State)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			if err := app.Runtime.Stop(ctx, p.ContainerID, 10*time.Second); err != nil {
				slog.Warn("error stopping container", "error", err)
			}

			if err := app.Runtime.Remove(ctx, p.ContainerID); err != nil {
				slog.Warn("error removing container", "error", err)
			}

			now := time.Now()
			p.State = plugin.StateStopped
			p.LastStopped = &now
			p.ContainerID = ""

			if err := app.Store.Put(p); err != nil {
				return fmt.Errorf("updating plugin state: %w", err)
			}

			fmt.Printf("Stopped plugin %q\n", name)
			return nil
		},
	}
}
