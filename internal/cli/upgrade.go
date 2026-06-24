package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/spf13/cobra"
)

func newUpgradeCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "upgrade <plugin>",
		Aliases: []string{"reinstall"},
		Short:   "Reinstall a plugin from the registry at the latest version",
		Long: `Pull the latest image for a plugin from the registry, re-read its manifest
and metadata from the image, and restart with the new version — preserving your
env overrides and enabled state.

If plugger is already running as a daemon, prefer doing this from the dashboard
so the running scheduler applies it without a race.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
			defer cancel()

			deps := &lifecycle.Deps{Store: app.Store, Runtime: app.Runtime, Config: app.Config}

			fmt.Printf("Reinstalling %s from registry...\n", name)
			oldVer, newVer, err := lifecycle.ReinstallFromRegistry(ctx, deps, name)
			if err != nil {
				return err
			}

			fmt.Printf("Upgraded %s: %s → %s\n", name, oldVer, newVer)
			return nil
		},
	}
}
