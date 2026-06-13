package cli

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/dashboard"
	"github.com/illumio/plugger/internal/health"
	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/reports"
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

			// Write PID file immediately so reload works
			pidFile := filepath.Join(app.Config.Plugger.DataDir, "plugger.pid")
			os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0644)
			defer os.Remove(pidFile)

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
			eventSchedulers := make(map[string]*scheduler.EventScheduler)
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
					es := scheduler.NewEventScheduler(deps, p)
					if err := es.Start(ctx); err != nil {
						slog.Error("failed to start event scheduler", "plugin", p.Name, "error", err)
						continue
					}
					schedulers[p.Name] = es
					eventSchedulers[p.Name] = es
					slog.Info("registered event plugin", "plugin", p.Name,
						"eventTypes", p.Manifest.Events.Types)

				default:
					slog.Warn("unknown schedule mode", "plugin", p.Name, "mode", p.Manifest.Schedule.Mode)
				}
			}

			activeCount := len(schedulers)
			slog.Info("orchestrator started", "plugins", activeCount)
			fmt.Printf("Plugger running: %d plugin(s) active\n", activeCount)

			// Set up event webhook registry
			eventRegistry := dashboard.NewEventRegistry(app.Config.Plugger.WebhookToken)
			for name, es := range eventSchedulers {
				eventRegistry.Register(name, es)
			}
			if len(eventSchedulers) > 0 {
				tok := eventRegistry.Token()
				fmt.Printf("Event webhook: POST http://%s/api/events/trigger (token: %s...)\n",
					addr, tok[:8])
			}

			// Set up report router
			var reportRouter *reports.Router
			if len(app.Config.Plugger.Outputs) > 0 {
				var err error
				reportRouter, err = reports.NewRouter(app.Config.Plugger.Outputs)
				if err != nil {
					slog.Warn("failed to initialize report router", "error", err)
				} else {
					slog.Info("report router initialized", "outputs", reportRouter.OutputCount())
				}
			}

			// Start dashboard
			if !noDashboard {
				handler := dashboard.NewHandler(app.Store, app.Runtime, app.Config, app.Logger)
				handler.SetEventRegistry(eventRegistry)
				if reportRouter != nil {
					handler.SetReportRouter(reportRouter)
				}
				mux := handler.WrappedRoutes()
				go func() {
					certFile, keyFile := resolveTLSCerts(app.Config)
					if certFile != "" && keyFile != "" {
						slog.Info("dashboard starting with TLS", "addr", addr)
						fmt.Printf("Dashboard: https://%s\n", addr)
						server := &http.Server{
							Addr:    addr,
							Handler: mux,
							TLSConfig: &tls.Config{
								MinVersion: tls.VersionTLS12,
							},
						}
						if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
							slog.Error("dashboard TLS error", "error", err)
						}
					} else {
						slog.Warn("dashboard starting WITHOUT TLS (no certs found)", "addr", addr)
						fmt.Printf("Dashboard: http://%s (no TLS)\n", addr)
						if err := http.ListenAndServe(addr, mux); err != nil {
							slog.Error("dashboard error", "error", err)
						}
					}
				}()
			}

			// Wait for shutdown or reload signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

		waitLoop:
			for {
				sig := <-sigCh

				if sig == syscall.SIGHUP {
					// Reload: re-read config, restart all plugins
					slog.Info("received SIGHUP — reloading config and restarting plugins")
					fmt.Println("\nReloading...")

					newCfg, reloadErr := config.Load(cfgFile)
					if reloadErr != nil {
						slog.Error("failed to reload config", "error", reloadErr)
						fmt.Printf("Reload failed: %v (keeping current config)\n", reloadErr)
						continue
					}

					// Update app config
					app.Config = newCfg
					deps.Config = newCfg

					// Restart all running plugins (they get new env vars from updated config)
					slog.Info("restarting all plugins with new config...")
					restartCtx, restartCancel := context.WithTimeout(context.Background(), 2*time.Minute)
					restarted := 0
					for name, sched := range schedulers {
						func() {
							defer func() {
								if r := recover(); r != nil {
									slog.Error("panic restarting plugin", "plugin", name, "panic", r)
								}
							}()
							slog.Info("restarting plugin", "plugin", name)
							if stopErr := sched.Stop(restartCtx); stopErr != nil {
								slog.Warn("error stopping plugin for reload", "plugin", name, "error", stopErr)
							}
							if startErr := sched.Start(restartCtx); startErr != nil {
								slog.Error("error restarting plugin", "plugin", name, "error", startErr)
							} else {
								restarted++
							}
						}()
					}
					restartCancel()

					slog.Info("reload complete", "plugins_restarted", restarted)
					fmt.Printf("Reloaded: %d plugin(s) restarted with new config\n", restarted)
					fmt.Printf("PCE: %s:%d (org %d)\n", newCfg.PCE.Host, newCfg.PCE.Port, newCfg.PCE.OrgID)
					continue
				}

				// SIGINT/SIGTERM — shutdown
				slog.Info("received shutdown signal", "signal", sig)
				fmt.Println("\nShutting down...")
				break waitLoop
			}

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

			if reportRouter != nil {
				reportRouter.Stop()
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
		} else if exists && running {
			if p.State != plugin.StateRunning {
				slog.Info("reconcile: container running, updating state", "plugin", p.Name)
			}
			// Check if container has stale PCE credentials
			if p.ContainerID != "" && hasStaleCredentials(ctx, deps, p) {
				slog.Info("reconcile: restarting plugin (PCE credentials changed)", "plugin", p.Name)
				_ = lifecycle.StopPlugin(ctx, deps, p)
				if err := lifecycle.StartPlugin(ctx, deps, p); err != nil {
					slog.Error("reconcile: failed to restart plugin", "plugin", p.Name, "error", err)
				}
			}
		}

		// Clean up stale stopped containers
		if exists && !running {
			slog.Info("reconcile: removing stopped container", "plugin", p.Name)
			_ = deps.Runtime.Remove(ctx, containerName)
		}
	}

	return nil
}

// hasStaleCredentials checks if a running container has different PCE
// credentials than the current config. Returns true if a restart is needed.
func hasStaleCredentials(ctx context.Context, deps *lifecycle.Deps, p *plugin.Plugin) bool {
	info, err := deps.Runtime.Inspect(ctx, p.ContainerID)
	if err != nil {
		return false
	}

	envMap := make(map[string]string)
	for _, e := range info.Env {
		if k, v, ok := strings.Cut(e, "="); ok {
			envMap[k] = v
		}
	}

	cfg := deps.Config.PCE
	if envMap["PCE_API_KEY"] != cfg.APIKey || envMap["PCE_API_SECRET"] != cfg.APISecret {
		return true
	}
	if envMap["PCE_HOST"] != cfg.Host {
		return true
	}
	return false
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

// resolveTLSCerts determines which TLS cert/key to use.
// Priority: 1) BYO cert from config  2) auto-generated self-signed  3) generate on the fly
// TLS is ON by default. Set plugger.tls.enabled: false to explicitly disable.
func resolveTLSCerts(cfg *config.Config) (certFile, keyFile string) {
	tlsCfg := cfg.Plugger.TLS

	// Only skip TLS if explicitly set to false in config
	// (Missing/zero value = enabled, since we want TLS by default)
	if tlsCfg.CertFile == "" && tlsCfg.KeyFile == "" && !tlsCfg.Enabled {
		// Check if there's no tls section at all (legacy config) — still enable TLS
		// Only disable if enabled is explicitly false AND no certs configured
		// We detect "explicitly set to false" vs "not set" by checking if certs exist
		dataDir := cfg.Plugger.DataDir
		if !config.TLSCertsExist(dataDir) {
			// No certs exist and TLS not enabled in config — skip
			return "", ""
		}
		// Certs exist from a previous init — use them even without config entry
	}

	// BYO certificate from config (highest priority)
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		if _, err := os.Stat(tlsCfg.CertFile); err == nil {
			if _, err := os.Stat(tlsCfg.KeyFile); err == nil {
				slog.Info("using BYO TLS certificate", "cert", tlsCfg.CertFile)
				return tlsCfg.CertFile, tlsCfg.KeyFile
			}
		}
		slog.Warn("BYO TLS cert/key not found, falling back to self-signed", "cert", tlsCfg.CertFile, "key", tlsCfg.KeyFile)
	}

	// Auto-generated self-signed
	dataDir := cfg.Plugger.DataDir
	if config.TLSCertsExist(dataDir) {
		slog.Info("using self-signed TLS certificate", "cert", config.TLSCertPath(dataDir))
		return config.TLSCertPath(dataDir), config.TLSKeyPath(dataDir)
	}

	// Generate on the fly if none exist
	certPath, keyPath, err := config.GenerateSelfSignedCert(dataDir)
	if err != nil {
		slog.Warn("failed to generate self-signed cert, running without TLS", "error", err)
		return "", ""
	}
	slog.Info("generated self-signed TLS certificate", "cert", certPath)
	return certPath, keyPath
}
