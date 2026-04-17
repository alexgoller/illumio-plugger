package cli

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/illumio/plugger/internal/registry"
	"github.com/spf13/cobra"
)

func newRepoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "repo",
		Short: "Manage plugin registries",
	}

	cmd.AddCommand(
		newRepoListCmd(),
		newRepoAddCmd(),
		newRepoRemoveCmd(),
	)

	return cmd
}

func newRepoListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured registries",
		Aliases: []string{"ls"},
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			repos, err := mgr.ListRepos()
			if err != nil {
				return err
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tURL")
			for _, r := range repos {
				fmt.Fprintf(w, "%s\t%s\n", r.Name, r.URL)
			}
			return w.Flush()
		},
	}
}

func newRepoAddCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <name> <url>",
		Short: "Add a custom plugin registry",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			if err := mgr.AddRepo(args[0], args[1]); err != nil {
				return err
			}
			fmt.Printf("Added registry %q (%s)\n", args[0], args[1])
			return nil
		},
	}
}

func newRepoRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove a custom plugin registry",
		Aliases: []string{"rm"},
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := registry.NewManager(app.Config.Plugger.DataDir)
			if err := mgr.RemoveRepo(args[0]); err != nil {
				return err
			}
			fmt.Printf("Removed registry %q\n", args[0])
			return nil
		},
	}
}
