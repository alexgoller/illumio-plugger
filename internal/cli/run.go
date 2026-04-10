package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/illumio/plugger/internal/dashboard"
	"github.com/illumio/plugger/internal/health"
	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/scheduler"
	"github.com/spf13/cobra"
)

func newRunCmd() *cobra.Command {
	var (
		addr        string
		noDashboard bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start all enabled plugins with scheduling, health checks, and dashboard",
		Long: `Run the plugger orchestrator. Starts all enabled plugins according to their
schedule mode (daemon or cron), monitors health, auto-restarts on crash,
and serves the web dashboard.

This is the production way to run plugger — suitable for systemd/launchd.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			deps := &lifecycle.Deps{
				Store:   app.Store,
				Runtime: app.Runtime,
				Config:  app.Config,
			}

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			// Reconcile stored state vs actual containers
			slog.Info("reconciling plugin state...")
			if err := reconcileState(ctx, deps); err != nil {
				slog.Warn("reconciliation error", "error", err)
			}

			// Load all plugins
			plugins, err := app.Store.List()
			if err != nil {
				return fmt.Errorf("listing plugins: %w", err)
			}

			schedulers := make(map[string]scheduler.Scheduler)
			checkers := make(map[string]*health.Checker)

			// Start each enabled plugin with appropriate scheduler
			for _, p := range plugins {
				if !p.Enabled {
					slog.Info("skipping disabled plugin", "plugin", p.Name)
					continue
				}

				switch p.Manifest.Schedule.Mode {
				case "daemon":
					ds := scheduler.NewDaemonScheduler(deps, p)
					if err := ds.Start(ctx); err != nil {
						slog.Error("failed to start daemon", "plugin", p.Name, "error", err)
						continue
					}
					schedulers[p.Name] = ds
					slog.Info("started daemon plugin", "plugin", p.Name)

					// Start health checker if configured
					checker := setupHealthChecker(ctx, deps, p, ds)
					if checker != nil {
						checkers[p.Name] = checker
					}

				case "cron":
					cs := scheduler.NewCronScheduler(deps, p)
					if err := cs.Start(ctx); err != nil {
						slog.Error("failed to start cron scheduler", "plugin", p.Name, "error", err)
						continue
					}
					schedulers[p.Name] = cs
					slog.Info("started cron plugin", "plugin", p.Name,
						"schedule", p.Manifest.Schedule.Cron)

				case "event":
					slog.Warn("event-driven scheduling not yet implemented", "plugin", p.Name)

				default:
					slog.Warn("unknown schedule mode", "plugin", p.Name, "mode", p.Manifest.Schedule.Mode)
				}
			}

			activeCount := len(schedulers)
			slog.Info("orchestrator started", "plugins", activeCount)
			fmt.Printf("Plugger running: %d plugin(s) active\n", activeCount)

			// Start dashboard
			if !noDashboard {
				handler := dashboard.NewHandler(app.Store, app.Runtime, app.Config, app.Logger)
				mux := handler.Routes()
				go func() {
					slog.Info("dashboard starting", "addr", addr)
					fmt.Printf("Dashboard: http://%s\n", addr)
					if err := http.ListenAndServe(addr, mux); err != nil {
						slog.Error("dashboard error", "error", err)
					}
				}()
			}

			// Wait for shutdown signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

			sig := <-sigCh
			slog.Info("received shutdown signal", "signal", sig)
			fmt.Println("\nShutting down...")

			cancel()

			// Stop health checkers
			for name, checker := range checkers {
				slog.Info("stopping health checker", "plugin", name)
				checker.Stop()
			}

			// Stop all schedulers
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer shutdownCancel()

			for name, sched := range schedulers {
				slog.Info("stopping plugin", "plugin", name)
				if err := sched.Stop(shutdownCtx); err != nil {
					slog.Warn("error stopping plugin", "plugin", name, "error", err)
				}
			}

			slog.Info("plugger stopped")
			fmt.Println("Stopped.")
			return nil
		},
	}

	cmd.Flags().StringVar(&addr, "addr", "localhost:8800", "dashboard listen address")
	cmd.Flags().BoolVar(&noDashboard, "no-dashboard", false, "run without the web dashboard")
	return cmd
}

// reconcileState syncs stored plugin state with actual Docker container state.
func reconcileState(ctx context.Context, deps *lifecycle.Deps) error {
	// Get actual containers
	containers, err := deps.Runtime.ListManaged(ctx)
	if err != nil {
		return fmt.Errorf("listing containers: %w", err)
	}

	containerByName := make(map[string]bool)
	for _, c := range containers {
		containerByName[c.Name] = c.Running
	}

	// Get stored plugins
	plugins, err := deps.Store.List()
	if err != nil {
		return fmt.Errorf("listing plugins: %w", err)
	}

	for _, p := range plugins {
		containerName := p.ContainerName()
		running, exists := containerByName[containerName]

		if p.State == plugin.StateRunning && (!exists || !running) {
			// Store says running but container is gone/stopped
			slog.Info("reconcile: marking as stopped (container missing)", "plugin", p.Name)
			p.State = plugin.StateStopped
			p.ContainerID = ""
			deps.Store.Put(p)
		} else if p.State != plugin.StateRunning && exists && running {
			// Container running but store doesn't know
			slog.Info("reconcile: container running, updating state", "plugin", p.Name)
			// We'll let the scheduler handle this on next start
		}

		// Clean up stale stopped containers
		if exists && !running {
			slog.Info("reconcile: removing stopped container", "plugin", p.Name)
			_ = deps.Runtime.Remove(ctx, containerName)
		}
	}

	return nil
}

// setupHealthChecker creates and starts a health checker for a daemon plugin if configured.
func setupHealthChecker(ctx context.Context, deps *lifecycle.Deps, p *plugin.Plugin, ds *scheduler.DaemonScheduler) *health.Checker {
	// Determine health config from manifest or metadata
	var endpoint string
	var port int
	var interval, timeout time.Duration
	var retries int

	if p.Manifest.Health != nil {
		endpoint = p.Manifest.Health.Endpoint
		port = p.Manifest.Health.Port
		interval = p.Manifest.Health.Interval
		timeout = p.Manifest.Health.Timeout
		retries = p.Manifest.Health.Retries
	} else if p.Metadata != nil && p.Metadata.HealthCheck != nil {
		endpoint = p.Metadata.HealthCheck.Endpoint
		port = p.Metadata.HealthCheck.Port
		interval = p.Metadata.HealthCheck.Interval
	}

	if endpoint == "" || port == 0 {
		return nil
	}

	// Discover actual host port
	if p.ContainerID != "" {
		info, err := deps.Runtime.Inspect(ctx, p.ContainerID)
		if err == nil {
			if hostPort, ok := info.Ports[port]; ok && hostPort > 0 {
				port = hostPort
			}
		}
	}

	url := fmt.Sprintf("http://localhost:%d%s", port, endpoint)
	slog.Info("starting health checker", "plugin", p.Name, "url", url, "interval", interval)

	checker := health.NewChecker(p.Name, url, interval, timeout, retries, func(name string, err error) {
		slog.Warn("health check failed, triggering restart", "plugin", name, "error", err)
		ds.TriggerRestart()
	})
	checker.Start(ctx)
	return checker
}
