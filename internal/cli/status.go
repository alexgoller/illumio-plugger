package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status <plugin>",
		Short: "Show detailed status of a plugin",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			fmt.Printf("Plugin:    %s\n", p.Name)
			fmt.Printf("Version:   %s\n", p.Manifest.Version)
			fmt.Printf("Image:     %s\n", p.Manifest.Image)
			fmt.Printf("Mode:      %s\n", p.Manifest.Schedule.Mode)
			fmt.Printf("State:     %s\n", p.State)
			fmt.Printf("Enabled:   %v\n", p.Enabled)
			fmt.Printf("Installed: %s\n", p.InstalledAt.Format(time.RFC3339))

			if p.LastStarted != nil {
				fmt.Printf("Started:   %s\n", p.LastStarted.Format(time.RFC3339))
			}
			if p.LastStopped != nil {
				fmt.Printf("Stopped:   %s\n", p.LastStopped.Format(time.RFC3339))
			}
			if p.LastError != "" {
				fmt.Printf("Error:     %s\n", p.LastError)
			}

			// Show live container info if running
			if p.ContainerID != "" {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()

				info, err := app.Runtime.Inspect(ctx, p.ContainerID)
				if err == nil {
					fmt.Printf("\nContainer:\n")
					fmt.Printf("  ID:      %s\n", info.ID[:12])
					fmt.Printf("  Status:  %s\n", info.Status)
					fmt.Printf("  Running: %v\n", info.Running)
				}
			}

			// Show env vars (mask secrets)
			if len(p.Manifest.Env) > 0 {
				fmt.Printf("\nEnvironment:\n")
				for _, e := range p.Manifest.Env {
					val := e.Default
					if override, ok := p.EnvOverrides[e.Name]; ok {
						val = override
					}
					if e.Secret {
						val = "***"
					}
					req := ""
					if e.Required {
						req = " (required)"
					}
					fmt.Printf("  %s=%s%s\n", e.Name, val, req)
				}
			}

			return nil
		},
	}
}
