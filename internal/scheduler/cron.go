package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/robfig/cron/v3"
)

// CronScheduler runs a plugin on a cron schedule.
type CronScheduler struct {
	deps   *lifecycle.Deps
	plugin *plugin.Plugin
	cron   *cron.Cron
	cancel context.CancelFunc
}

// NewCronScheduler creates a scheduler for a cron-mode plugin.
func NewCronScheduler(deps *lifecycle.Deps, p *plugin.Plugin) *CronScheduler {
	return &CronScheduler{
		deps:   deps,
		plugin: p,
	}
}

func (c *CronScheduler) Name() string { return c.plugin.Name }

// Start begins the cron schedule.
func (c *CronScheduler) Start(ctx context.Context) error {
	ctx, c.cancel = context.WithCancel(ctx)

	c.cron = cron.New()
	entryID, err := c.cron.AddFunc(c.plugin.Manifest.Schedule.Cron, func() {
		c.executeRun(ctx)
	})
	if err != nil {
		return err
	}

	c.cron.Start()

	// Compute and store next run time
	entry := c.cron.Entry(entryID)
	next := entry.Next
	c.plugin.NextRun = &next
	c.deps.Store.Put(c.plugin)

	slog.Info("cron scheduler started", "plugin", c.plugin.Name,
		"schedule", c.plugin.Manifest.Schedule.Cron, "nextRun", next)

	return nil
}

// Stop stops the cron scheduler.
func (c *CronScheduler) Stop(ctx context.Context) error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.cron != nil {
		stopCtx := c.cron.Stop()
		// Wait for running jobs to finish (with timeout)
		select {
		case <-stopCtx.Done():
		case <-time.After(60 * time.Second):
			slog.Warn("cron stop timed out", "plugin", c.plugin.Name)
		}
	}
	return nil
}

func (c *CronScheduler) executeRun(ctx context.Context) {
	slog.Info("cron triggered", "plugin", c.plugin.Name)

	if err := lifecycle.StartPlugin(ctx, c.deps, c.plugin); err != nil {
		slog.Error("cron run: start failed", "plugin", c.plugin.Name, "error", err)
		c.plugin.LastError = err.Error()
		c.deps.Store.Put(c.plugin)
		return
	}

	// Wait for container to exit
	if c.plugin.ContainerID != "" {
		waitCh, err := c.deps.Runtime.Wait(ctx, c.plugin.ContainerID)
		if err != nil {
			slog.Error("cron run: wait failed", "plugin", c.plugin.Name, "error", err)
		} else {
			select {
			case <-ctx.Done():
				return
			case result := <-waitCh:
				exitCode := int(result.StatusCode)
				c.plugin.LastExitCode = &exitCode
				now := time.Now()
				c.plugin.LastStopped = &now

				if exitCode != 0 {
					slog.Warn("cron run exited non-zero", "plugin", c.plugin.Name, "exitCode", exitCode)
					c.plugin.LastError = "exit code " + string(rune('0'+exitCode))
				} else {
					slog.Info("cron run completed", "plugin", c.plugin.Name)
					c.plugin.LastError = ""
				}
			}
		}

		// Cleanup container
		_ = c.deps.Runtime.Remove(ctx, c.plugin.ContainerID)
	}

	// Update state back to installed (idle)
	c.plugin.State = plugin.StateInstalled
	c.plugin.ContainerID = ""

	// Compute next run
	entries := c.cron.Entries()
	if len(entries) > 0 {
		next := entries[0].Next
		c.plugin.NextRun = &next
	}

	c.deps.Store.Put(c.plugin)
}
