package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	ct "github.com/illumio/plugger/internal/container"
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

			// Ensure network
			if err := ct.SetupNetwork(ctx, app.Runtime, app.Config.Plugger.Network); err != nil {
				return err
			}

			// Recreate and start
			env := p.BuildEnv(app.Config.PCE)
			labels := map[string]string{
				ct.LabelManaged: "true",
				ct.LabelPlugin:  p.Name,
				ct.LabelVersion: p.Manifest.Version,
				ct.LabelMode:    p.Manifest.Schedule.Mode,
			}

			var memory int64
			if p.Manifest.Resources != nil {
				memory = parseMemory(p.Manifest.Resources.MemoryLimit)
			}
			var cpus string
			if p.Manifest.Resources != nil {
				cpus = p.Manifest.Resources.CPULimit
			}

			containerID, err := app.Runtime.Create(ctx, ct.CreateOpts{
				Name:    p.ContainerName(),
				Image:   p.Manifest.Image,
				Env:     env,
				Network: app.Config.Plugger.Network,
				Labels:  labels,
				Memory:  memory,
				CPUs:    cpus,
			})
			if err != nil {
				return fmt.Errorf("creating container: %w", err)
			}

			if err := app.Runtime.Start(ctx, containerID); err != nil {
				_ = app.Runtime.Remove(ctx, containerID)
				return fmt.Errorf("starting container: %w", err)
			}

			now := time.Now()
			p.ContainerID = containerID
			p.State = plugin.StateRunning
			p.LastStarted = &now
			p.LastError = ""

			if err := app.Store.Put(p); err != nil {
				return fmt.Errorf("updating plugin state: %w", err)
			}

			fmt.Printf("Restarted plugin %q (container %s)\n", name, containerID[:12])
			return nil
		},
	}
}
