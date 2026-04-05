package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
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

			fmt.Printf("Restarting plugin %q...\n", name)
			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}
			if err := lifecycle.RestartPlugin(ctx, deps, p); err != nil {
				return err
			}

			fmt.Printf("Restarted plugin %q (container %s)\n", name, p.ContainerID[:12])
			return nil
		},
	}
}
