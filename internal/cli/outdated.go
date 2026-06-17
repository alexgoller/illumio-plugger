package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newOutdatedCmd() *cobra.Command {
	var pull bool

	cmd := &cobra.Command{
		Use:   "outdated",
		Short: "Check for plugin updates",
		Long: `Check installed plugins against the registry for version updates.

With --pull, also checks if the remote Docker image has a newer digest
than the local one (catches :latest tag updates).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check for plugger CLI updates
			if latest, err := checkLatestRelease(); err == nil && latest != "" {
				current := Version
				if current != "dev" && current != latest {
					fmt.Printf("Plugger update available: %s → %s\n", current, latest)
					fmt.Printf("  Download: https://github.com/alexgoller/illumio-plugger/releases/tag/%s\n\n", latest)
				}
			}

			plugins, err := app.Store.List()
			if err != nil {
				return err
			}

			installed := make(map[string]string)
			imageByPlugin := make(map[string]string)
			for _, p := range plugins {
				installed[p.Name] = p.Manifest.Version
				imageByPlugin[p.Name] = p.Manifest.Image
			}

			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			updates, err := mgr.CheckUpdates(installed)
			if err != nil {
				return err
			}

			// Check for new plugins in registry that aren't installed
			registries, _ := mgr.FetchAll()
			var available []registry.Plugin
			for _, reg := range registries {
				for _, p := range reg.Plugins {
					if _, ok := installed[p.Name]; !ok {
						available = append(available, p)
					}
				}
			}

			// Check for image digest changes (--pull)
			type digestUpdate struct {
				Name       string
				Image      string
				LocalHash  string
				RemoteHash string
			}
			var digestUpdates []digestUpdate

			if pull {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				for _, p := range plugins {
					image := p.Manifest.Image
					if image == "" {
						continue
					}

					localDigest, err := app.Runtime.ImageDigest(ctx, image)
					if err != nil || localDigest == "" {
						continue
					}

					fmt.Printf("Pulling %s...\n", image)
					if err := app.Runtime.Pull(ctx, image); err != nil {
						fmt.Printf("  warning: pull failed: %s\n", err)
						continue
					}

					remoteDigest, err := app.Runtime.ImageDigest(ctx, image)
					if err != nil || remoteDigest == "" {
						continue
					}

					if localDigest != remoteDigest {
						digestUpdates = append(digestUpdates, digestUpdate{
							Name:       p.Name,
							Image:      image,
							LocalHash:  localDigest[:16],
							RemoteHash: remoteDigest[:16],
						})
					}
				}
			}

			// Output
			hasOutput := false

			if len(updates) > 0 {
				hasOutput = true
				fmt.Println("Version updates available:")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  PLUGIN\tINSTALLED\tLATEST\tREGISTRY")
				for _, u := range updates {
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", u.Name, u.InstalledVersion, u.LatestVersion, u.Registry)
				}
				w.Flush()
				fmt.Println()
			}

			if len(digestUpdates) > 0 {
				hasOutput = true
				fmt.Println("Image updates available (newer :latest):")
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  PLUGIN\tIMAGE\tLOCAL\tREMOTE")
				for _, d := range digestUpdates {
					fmt.Fprintf(w, "  %s\t%s\t%s…\t%s…\n", d.Name, d.Image, d.LocalHash, d.RemoteHash)
				}
				w.Flush()
				fmt.Println("\nRestart plugins to use the new images: plugger restart <name>")
				fmt.Println()
			}

			if len(available) > 0 {
				hasOutput = true
				fmt.Printf("New plugins available (%d not installed):\n", len(available))
				w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
				fmt.Fprintln(w, "  NAME\tVERSION\tMODE\tDESCRIPTION")
				for _, p := range available {
					desc := p.Description
					if len(desc) > 60 {
						desc = desc[:57] + "..."
					}
					fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", p.Name, p.Version, p.Mode, desc)
				}
				w.Flush()
				fmt.Println()
			}

			if !hasOutput {
				fmt.Println("All plugins are up to date.")
				if !pull {
					fmt.Println("Tip: use --pull to also check for newer Docker images")
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&pull, "pull", false, "pull latest images and check for digest changes")
	return cmd
}

func checkLatestRelease() (string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/alexgoller/illumio-plugger/releases/latest")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	return strings.TrimPrefix(release.TagName, "v"), nil
}
