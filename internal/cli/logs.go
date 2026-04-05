package cli

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/illumio/plugger/internal/container"
	"github.com/spf13/cobra"
)

func newLogsCmd() *cobra.Command {
	var (
		follow bool
		tail   string
		since  string
	)

	cmd := &cobra.Command{
		Use:   "logs <plugin>",
		Short: "View logs from a plugin container",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			p, err := app.Store.Get(name)
			if err != nil {
				return err
			}

			if p.ContainerID == "" {
				return fmt.Errorf("plugin %q has no container (state: %s)", name, p.State)
			}

			ctx := context.Background()
			if !follow {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
			}

			reader, err := app.Runtime.Logs(ctx, p.ContainerID, container.LogOpts{
				Follow: follow,
				Tail:   tail,
				Since:  since,
			})
			if err != nil {
				return fmt.Errorf("getting logs: %w", err)
			}
			defer reader.Close()

			_, err = io.Copy(os.Stdout, reader)
			return err
		},
	}

	cmd.Flags().BoolVarP(&follow, "follow", "f", false, "follow log output")
	cmd.Flags().StringVarP(&tail, "tail", "n", "100", "number of lines to show from the end")
	cmd.Flags().StringVar(&since, "since", "", "show logs since timestamp or relative (e.g. 1h)")

	return cmd
}
