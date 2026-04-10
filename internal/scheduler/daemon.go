package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

// DaemonScheduler runs a plugin continuously and auto-restarts on crash
// with exponential backoff.
type DaemonScheduler struct {
	deps   *lifecycle.Deps
	plugin *plugin.Plugin

	mu               sync.Mutex
	cancel           context.CancelFunc
	done             chan struct{}
	consecutiveFails int
	maxFails         int
	backoffBase      time.Duration
	backoffCap       time.Duration
	restartCh        chan struct{} // signals a forced restart (from health check)
}

// NewDaemonScheduler creates a scheduler for a daemon-mode plugin.
func NewDaemonScheduler(deps *lifecycle.Deps, p *plugin.Plugin) *DaemonScheduler {
	return &DaemonScheduler{
		deps:        deps,
		plugin:      p,
		done:        make(chan struct{}),
		restartCh:   make(chan struct{}, 1),
		maxFails:    5,
		backoffBase: 1 * time.Second,
		backoffCap:  5 * time.Minute,
	}
}

func (d *DaemonScheduler) Name() string { return d.plugin.Name }

// Start launches the plugin and watches for crashes.
func (d *DaemonScheduler) Start(ctx context.Context) error {
	ctx, d.cancel = context.WithCancel(ctx)

	// Initial start
	if err := lifecycle.StartPlugin(ctx, d.deps, d.plugin); err != nil {
		slog.Error("failed to start daemon plugin", "plugin", d.plugin.Name, "error", err)
		d.plugin.State = plugin.StateErrored
		d.plugin.LastError = err.Error()
		d.deps.Store.Put(d.plugin)
		// Don't return error — let the watch loop retry
	}

	go d.watchLoop(ctx)
	return nil
}

// Stop gracefully stops the daemon.
func (d *DaemonScheduler) Stop(ctx context.Context) error {
	if d.cancel != nil {
		d.cancel()
	}
	// Wait for watch loop to exit (with timeout)
	select {
	case <-d.done:
	case <-time.After(35 * time.Second):
		slog.Warn("daemon scheduler stop timed out", "plugin", d.plugin.Name)
	}
	return lifecycle.StopPlugin(ctx, d.deps, d.plugin)
}

// TriggerRestart forces a restart (called by health checker on failure).
func (d *DaemonScheduler) TriggerRestart() {
	select {
	case d.restartCh <- struct{}{}:
	default:
	}
}

func (d *DaemonScheduler) watchLoop(ctx context.Context) {
	defer close(d.done)

	for {
		// Wait for container exit or forced restart
		if d.plugin.ContainerID != "" {
			waitCh, err := d.deps.Runtime.Wait(ctx, d.plugin.ContainerID)
			if err == nil {
				select {
				case <-ctx.Done():
					return
				case result := <-waitCh:
					if ctx.Err() != nil {
						return
					}
					exitCode := int(result.StatusCode)
					d.plugin.LastExitCode = &exitCode
					if result.Err != nil {
						slog.Warn("container wait error", "plugin", d.plugin.Name, "error", result.Err)
					} else {
						slog.Warn("daemon container exited", "plugin", d.plugin.Name, "exitCode", exitCode)
					}
				case <-d.restartCh:
					slog.Info("forced restart requested", "plugin", d.plugin.Name)
					_ = lifecycle.StopPlugin(ctx, d.deps, d.plugin)
				}
			}
		}

		if ctx.Err() != nil {
			return
		}

		d.mu.Lock()
		d.consecutiveFails++
		fails := d.consecutiveFails
		d.mu.Unlock()

		if fails > d.maxFails {
			slog.Error("daemon exceeded max restart attempts", "plugin", d.plugin.Name, "attempts", fails)
			d.plugin.State = plugin.StateErrored
			d.plugin.LastError = "exceeded max restart attempts"
			d.deps.Store.Put(d.plugin)
			return
		}

		// Exponential backoff
		backoff := d.backoffBase
		for i := 1; i < fails; i++ {
			backoff *= 2
			if backoff > d.backoffCap {
				backoff = d.backoffCap
				break
			}
		}

		slog.Info("restarting daemon", "plugin", d.plugin.Name, "attempt", fails, "backoff", backoff)

		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		if err := lifecycle.StartPlugin(ctx, d.deps, d.plugin); err != nil {
			slog.Error("restart failed", "plugin", d.plugin.Name, "error", err)
			d.plugin.LastError = err.Error()
			d.deps.Store.Put(d.plugin)
			continue
		}

		// Reset fails after successful start + stability window
		go func() {
			select {
			case <-ctx.Done():
			case <-time.After(30 * time.Second):
				d.mu.Lock()
				d.consecutiveFails = 0
				d.mu.Unlock()
				slog.Info("daemon stable, reset backoff", "plugin", d.plugin.Name)
			}
		}()
	}
}
