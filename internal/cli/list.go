package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

func newListCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List all installed plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			plugins, err := app.Store.List()
			if err != nil {
				return err
			}

			if len(plugins) == 0 {
				fmt.Println("No plugins installed.")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tVERSION\tMODE\tSTATE\tENABLED")
			for _, p := range plugins {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%v\n",
					p.Name,
					p.Manifest.Version,
					p.Manifest.Schedule.Mode,
					p.State,
					p.Enabled,
				)
			}
			return w.Flush()
		},
	}
}
