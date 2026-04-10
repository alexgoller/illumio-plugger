package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/config"
	ct "github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newInstallCmd() *cobra.Command {
	var envOverrides []string

	cmd := &cobra.Command{
		Use:   "install <manifest.yaml | URL | image-ref>",
		Short: "Install a plugin from a manifest file, URL, or container image",
		Long: `Install a plugin from:
  - Local manifest file: plugger install ./plugin.yaml
  - Remote URL:          plugger install https://example.com/plugin.yaml
  - Container image:     plugger install ghcr.io/org/plugin:v1.0`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			source := args[0]

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			var manifest *config.PluginManifest
			var metadata *config.ContainerMetadata
			var err error

			// Resolve source type
			switch {
			case strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://"):
				// Remote URL → fetch manifest
				fmt.Printf("Fetching manifest from %s...\n", source)
				manifest, err = fetchManifestFromURL(source)
				if err != nil {
					return fmt.Errorf("fetching manifest: %w", err)
				}

			case isImageRef(source):
				// Container image ref → pull and extract manifest from image
				fmt.Printf("Pulling image %s...\n", source)
				if pullErr := app.Runtime.Pull(ctx, source); pullErr != nil {
					return fmt.Errorf("pulling image: %w", pullErr)
				}

				// Try to extract manifest from image
				manifestBytes, mErr := app.Runtime.CopyFromImage(ctx, source, "/.plugger/manifest.yaml")
				if mErr != nil {
					// Fallback: try plugin.yaml
					manifestBytes, mErr = app.Runtime.CopyFromImage(ctx, source, "/.plugger/plugin.yaml")
				}
				if mErr != nil {
					return fmt.Errorf("image %s does not contain /.plugger/manifest.yaml or /.plugger/plugin.yaml", source)
				}
				manifest, err = config.LoadManifestFromBytes(manifestBytes)
				if err != nil {
					return fmt.Errorf("parsing manifest from image: %w", err)
				}
				// Override image to match what was pulled
				manifest.Image = source

				// Extract metadata too
				metadataBytes, mdErr := app.Runtime.CopyFromImage(ctx, source, "/.plugger/metadata.yaml")
				if mdErr == nil {
					metadata, _ = config.ParseMetadata(metadataBytes)
				}

			default:
				// Local file
				manifest, err = config.LoadManifest(source)
				if err != nil {
					return err
				}
			}

			// Check if already installed
			if existing, _ := app.Store.Get(manifest.Name); existing != nil {
				return fmt.Errorf("plugin %q is already installed (use uninstall first)", manifest.Name)
			}

			// Pull image (if not already pulled via image-ref path)
			if !isImageRef(source) {
				fmt.Printf("Pulling image %s...\n", manifest.Image)
				if err := app.Runtime.Pull(ctx, manifest.Image); err != nil {
					// Check if image exists locally
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
			}

			// Discover in-container metadata (skip if already obtained from image-ref)
			if metadata == nil {
				metadataBytes, mdErr := app.Runtime.CopyFromImage(ctx, manifest.Image, "/.plugger/metadata.yaml")
				if mdErr != nil {
					slog.Info("no in-container metadata found (optional)", "plugin", manifest.Name, "error", mdErr)
				} else {
					metadata, err = config.ParseMetadata(metadataBytes)
					if err != nil {
						return fmt.Errorf("parsing container metadata: %w", err)
					}
				}
			}
			if metadata != nil {
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

// fetchManifestFromURL downloads a manifest YAML from a URL.
func fetchManifestFromURL(url string) (*config.PluginManifest, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return config.LoadManifestFromBytes(data)
}

// isImageRef returns true if the source looks like a container image reference
// (e.g. ghcr.io/org/plugin:v1.0) rather than a file path or URL.
func isImageRef(source string) bool {
	if strings.HasPrefix(source, "http://") || strings.HasPrefix(source, "https://") {
		return false
	}
	if strings.HasSuffix(source, ".yaml") || strings.HasSuffix(source, ".yml") {
		return false
	}
	// Image refs contain / (registry/repo) or : (tag)
	return strings.Contains(source, "/") || strings.Contains(source, ":")
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
