package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newStartCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "start <plugin>",
		Short: "Start a plugin container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			if p.State == plugin.StateRunning {
				return fmt.Errorf("plugin %q is already running", name)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			if p.ContainerID != "" {
				_ = app.Runtime.Remove(ctx, p.ContainerID)
			}

			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}
			if err := lifecycle.StartPlugin(ctx, deps, p); err != nil {
				return err
			}

			fmt.Printf("Started plugin %q (container %s)\n", name, p.ContainerID[:12])
			if p.Metadata != nil {
				for _, ps := range p.Metadata.Ports {
					if ps.Type == "ui" || ps.Type == "api" {
						path := ps.Path
						if path == "" {
							path = "/"
						}
						fmt.Printf("  %s: http://localhost:%d%s\n", ps.Name, ps.Port, path)
					} else {
						fmt.Printf("  %s: port %d/%s\n", ps.Name, ps.Port, ps.Protocol)
					}
				}
			}
			return nil
		},
	}
}
