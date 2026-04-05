package cli

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/illumio/plugger/internal/dashboard"
	"github.com/spf13/cobra"
)

func newDashboardCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Start the web dashboard for managing plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			handler := dashboard.NewHandler(app.Store, app.Runtime, app.Config, app.Logger)
			mux := handler.Routes()

			slog.Info("starting dashboard", "addr", addr)
			fmt.Printf("Plugger Dashboard: http://%s\n", addr)

			return http.ListenAndServe(addr, mux)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "localhost:8800", "listen address (host:port)")
	return cmd
}
