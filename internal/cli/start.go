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

			// Remove old container if it exists
			if p.ContainerID != "" {
				_ = app.Runtime.Remove(ctx, p.ContainerID)
			}

			// Ensure network exists
			if err := ct.SetupNetwork(ctx, app.Runtime, app.Config.Plugger.Network); err != nil {
				return err
			}

			// Build env and create container
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

			slog.Info("plugin started", "name", name, "container", containerID[:12])
			fmt.Printf("Started plugin %q (container %s)\n", name, containerID[:12])
			return nil
		},
	}
}

// parseMemory converts strings like "256m", "1g" to bytes.
func parseMemory(s string) int64 {
	if s == "" {
		return 0
	}
	n := int64(0)
	multiplier := int64(1)
	for i, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		} else {
			switch s[i:] {
			case "k", "K":
				multiplier = 1024
			case "m", "M":
				multiplier = 1024 * 1024
			case "g", "G":
				multiplier = 1024 * 1024 * 1024
			}
			break
		}
	}
	return n * multiplier
}
