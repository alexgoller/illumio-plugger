package cli

import (
	"crypto/tls"
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

			certFile, keyFile := resolveTLSCerts(app.Config)
			if certFile != "" && keyFile != "" {
				slog.Info("starting dashboard with TLS", "addr", addr)
				fmt.Printf("Plugger Dashboard: https://%s\n", addr)
				server := &http.Server{
					Addr:    addr,
					Handler: mux,
					TLSConfig: &tls.Config{
						MinVersion: tls.VersionTLS12,
					},
				}
				return server.ListenAndServeTLS(certFile, keyFile)
			}

			slog.Warn("starting dashboard WITHOUT TLS", "addr", addr)
			fmt.Printf("Plugger Dashboard: http://%s (no TLS)\n", addr)
			return http.ListenAndServe(addr, mux)
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "localhost:8800", "listen address (host:port)")
	return cmd
}
