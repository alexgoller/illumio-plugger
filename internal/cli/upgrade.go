package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:     "upgrade [plugin]",
		Aliases: []string{"reinstall"},
		Short:   "Reinstall a plugin (or all) from the registry at the latest version",
		Long: `Pull the latest image for a plugin from the registry, re-read its manifest
and metadata from the image, and restart with the new version — preserving your
env overrides and enabled state.

Use --all to upgrade every plugin that has a newer version in the registry.

If plugger is already running as a daemon, prefer doing this from the dashboard
so the running scheduler applies it without a race.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()

			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}

			if all {
				if len(args) > 0 {
					return fmt.Errorf("cannot combine --all with a plugin name")
				}
				return upgradeAll(ctx, deps)
			}

			if len(args) == 0 {
				return fmt.Errorf("specify a plugin name, or use --all to upgrade everything")
			}

			name := args[0]
			fmt.Printf("Reinstalling %s from registry...\n", name)
			oldVer, newVer, err := lifecycle.ReinstallFromRegistry(ctx, deps, name)
			if err != nil {
				return err
			}
			fmt.Printf("Upgraded %s: %s → %s\n", name, oldVer, newVer)
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "upgrade all plugins that have a newer version in the registry")
	return cmd
}

// upgradeAll reinstalls every installed plugin that the registry reports as
// outdated. Each is attempted independently; failures are reported and don't
// abort the rest.
func upgradeAll(ctx context.Context, deps *lifecycle.Deps) error {
	plugins, err := app.Store.List()
	if err != nil {
		return err
	}

	installed := make(map[string]string, len(plugins))
	for _, p := range plugins {
		installed[p.Name] = p.Manifest.Version
	}

	mgr := registry.NewManager(app.Config.Plugger.DataDir)
	updates, err := mgr.CheckUpdates(installed)
	if err != nil {
		return fmt.Errorf("checking registry: %w", err)
	}

	if len(updates) == 0 {
		fmt.Println("All plugins are up to date.")
		return nil
	}

	fmt.Printf("Upgrading %d plugin(s)...\n\n", len(updates))
	failed := 0
	for _, u := range updates {
		fmt.Printf("  %s: %s → %s ... ", u.Name, u.InstalledVersion, u.LatestVersion)
		if _, _, err := lifecycle.ReinstallFromRegistry(ctx, deps, u.Name); err != nil {
			fmt.Printf("FAILED: %v\n", err)
			failed++
			continue
		}
		fmt.Println("done")
	}

	fmt.Printf("\nUpgraded %d of %d plugin(s)\n", len(updates)-failed, len(updates))
	if failed > 0 {
		return fmt.Errorf("%d plugin(s) failed to upgrade", failed)
	}
	return nil
}
