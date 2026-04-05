package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
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

			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}
			if err := lifecycle.StopPlugin(ctx, deps, p); err != nil {
				return err
			}

			fmt.Printf("Stopped plugin %q\n", name)
			return nil
		},
	}
}
