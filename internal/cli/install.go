package cli

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/config"
	ct "github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	var envOverrides []string

	cmd := &cobra.Command{
		Use:   "install <manifest.yaml>",
		Short: "Install a plugin from a manifest file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestPath := args[0]

			manifest, err := config.LoadManifest(manifestPath)
			if err != nil {
				return err
			}

			// Check if already installed
			if existing, _ := app.Store.Get(manifest.Name); existing != nil {
				return fmt.Errorf("plugin %q is already installed (use uninstall first)", manifest.Name)
			}

			// Pull image (if pull fails, check if it exists locally)
			fmt.Printf("Pulling image %s...\n", manifest.Image)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			if err := app.Runtime.Pull(ctx, manifest.Image); err != nil {
				// Check if image exists locally (e.g. locally built images)
				_, inspectErr := app.Runtime.CopyFromImage(ctx, manifest.Image, "/.plugger/metadata.yaml")
				_ = inspectErr // we just need to verify the image is usable
				// Try creating a throwaway container to verify the image exists
				testID, createErr := app.Runtime.Create(ctx, ct.CreateOpts{
					Name:  "plugger-install-check-" + manifest.Name,
					Image: manifest.Image,
				})
				if createErr != nil {
					return fmt.Errorf("image %s not found locally and pull failed: %w", manifest.Image, err)
				}
				_ = app.Runtime.Remove(ctx, testID)
				fmt.Printf("Using local image %s (pull failed: %v)\n", manifest.Image, err)
			}

			// Discover in-container metadata
			var metadata *config.ContainerMetadata
			metadataBytes, err := app.Runtime.CopyFromImage(ctx, manifest.Image, "/.plugger/metadata.yaml")
			if err != nil {
				slog.Info("no in-container metadata found (optional)", "plugin", manifest.Name, "error", err)
			} else {
				metadata, err = config.ParseMetadata(metadataBytes)
				if err != nil {
					return fmt.Errorf("parsing container metadata: %w", err)
				}
				slog.Info("discovered container metadata", "plugin", manifest.Name)
				if metadata.Info != nil {
					fmt.Printf("  Plugin: %s\n", metadata.Info.Title)
					if metadata.Info.Description != "" {
						fmt.Printf("  %s\n", metadata.Info.Description)
					}
				}
				if len(metadata.Ports) > 0 {
					fmt.Printf("  Ports:\n")
					for _, p := range metadata.Ports {
						fmt.Printf("    %d/%s (%s) — %s\n", p.Port, p.Protocol, p.Name, p.Description)
					}
				}
				if len(metadata.Volumes) > 0 {
					fmt.Printf("  Volumes:\n")
					for _, v := range metadata.Volumes {
						req := ""
						if v.Required {
							req = " (required)"
						}
						fmt.Printf("    %s — %s%s\n", v.Path, v.Description, req)
					}
				}
				if len(metadata.Config) > 0 {
					fmt.Printf("  Config:\n")
					for _, c := range metadata.Config {
						req := ""
						if c.Required {
							req = " (required)"
						}
						fmt.Printf("    %s — %s%s\n", c.Name, c.Description, req)
					}
				}
			}

			// Parse env overrides
			overrides := parseEnvOverrides(envOverrides)

			// Validate required env vars from both manifest and discovered metadata
			for _, e := range manifest.Env {
				if e.Required && e.Default == "" {
					if _, ok := overrides[e.Name]; !ok {
						return fmt.Errorf("required env var %s not provided (use --env %s=VALUE)", e.Name, e.Name)
					}
				}
			}
			if metadata != nil {
				for _, c := range metadata.Config {
					if c.Required && c.Default == "" {
						if _, ok := overrides[c.Name]; !ok {
							// Check if already declared in manifest env
							inManifest := false
							for _, e := range manifest.Env {
								if e.Name == c.Name {
									inManifest = true
									break
								}
							}
							if !inManifest {
								return fmt.Errorf("required config %s not provided (discovered from container, use --env %s=VALUE)", c.Name, c.Name)
							}
						}
					}
				}
			}

			// Save plugin
			p := &plugin.Plugin{
				Name:         manifest.Name,
				Manifest:     *manifest,
				Metadata:     metadata,
				State:        plugin.StateInstalled,
				Enabled:      true,
				EnvOverrides: overrides,
				InstalledAt:  time.Now(),
			}

			if err := app.Store.Put(p); err != nil {
				return fmt.Errorf("saving plugin: %w", err)
			}

			slog.Info("plugin installed", "name", manifest.Name, "image", manifest.Image, "mode", manifest.Schedule.Mode)
			fmt.Printf("Installed plugin %q (%s, mode=%s)\n", manifest.Name, manifest.Version, manifest.Schedule.Mode)
			return nil
		},
	}

	cmd.Flags().StringArrayVarP(&envOverrides, "env", "e", nil, "environment variable overrides (KEY=VALUE)")
	return cmd
}

func parseEnvOverrides(pairs []string) map[string]string {
	result := make(map[string]string)
	for _, pair := range pairs {
		for i := 0; i < len(pair); i++ {
			if pair[i] == '=' {
				result[pair[:i]] = pair[i+1:]
				break
			}
		}
	}
	return result
}
