package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "search [query]",
		Short: "Search available plugins in registries",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			query := ""
			if len(args) > 0 {
				query = args[0]
			}

			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			plugins, err := mgr.Search(query)
			if err != nil {
				return err
			}

			if len(plugins) == 0 {
				fmt.Println("No plugins found.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tMODE\tDESCRIPTION")
			for _, p := range plugins {
				desc := p.Description
				if len(desc) > 60 {
					desc = desc[:57] + "..."
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Mode, desc)
			}
			return w.Flush()
		},
	}
}
