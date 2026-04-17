package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newOutdatedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "outdated",
		Short: "Check for plugin updates",
		RunE: func(cmd *cobra.Command, args []string) error {
			plugins, err := app.Store.List()
			if err != nil {
				return err
			}

			installed := make(map[string]string)
			for _, p := range plugins {
				installed[p.Name] = p.Manifest.Version
			}

			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			updates, err := mgr.CheckUpdates(installed)
			if err != nil {
				return err
			}

			if len(updates) == 0 {
				fmt.Println("All plugins are up to date.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "PLUGIN\tINSTALLED\tLATEST\tREGISTRY")
			for _, u := range updates {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", u.Name, u.InstalledVersion, u.LatestVersion, u.Registry)
			}
			return w.Flush()
		},
	}
}
