package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	ct "github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

// EventScheduler manages event-driven plugins that run ephemeral containers
// when triggered by external webhooks (e.g. from pce-events).
type EventScheduler struct {
	deps   *lifecycle.Deps
	plugin *plugin.Plugin

	mu             sync.Mutex
	cancel         context.CancelFunc
	ctx            context.Context
	maxConcurrent  int
	running        int
	totalTriggered int
	totalSuccess   int
	totalFailed    int
}

// NewEventScheduler creates a scheduler for an event-mode plugin.
func NewEventScheduler(deps *lifecycle.Deps, p *plugin.Plugin) *EventScheduler {
	return &EventScheduler{
		deps:          deps,
		plugin:        p,
		maxConcurrent: 5,
	}
}

func (e *EventScheduler) Name() string { return e.plugin.Name }

// Start prepares the event scheduler (no containers started until triggered).
func (e *EventScheduler) Start(ctx context.Context) error {
	e.ctx, e.cancel = context.WithCancel(ctx)
	types := []string{"*"}
	if e.plugin.Manifest.Events != nil {
		types = e.plugin.Manifest.Events.Types
	}
	slog.Info("event scheduler ready", "plugin", e.plugin.Name,
		"eventTypes", types, "maxConcurrent", e.maxConcurrent)
	return nil
}

// Stop cancels any running event containers.
func (e *EventScheduler) Stop(ctx context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	deadline := time.After(30 * time.Second)
	for {
		e.mu.Lock()
		r := e.running
		e.mu.Unlock()
		if r == 0 {
			break
		}
		select {
		case <-deadline:
			slog.Warn("event scheduler stop timed out", "plugin", e.plugin.Name, "running", r)
			return nil
		case <-time.After(500 * time.Millisecond):
		}
	}
	return nil
}

// MatchesEvent returns true if this plugin subscribes to the given event type.
func (e *EventScheduler) MatchesEvent(eventType string) bool {
	if e.plugin.Manifest.Events == nil {
		return false
	}
	for _, t := range e.plugin.Manifest.Events.Types {
		if t == eventType || t == "*" {
			return true
		}
	}
	return false
}

// Trigger spawns an ephemeral container to process the given event.
func (e *EventScheduler) Trigger(event json.RawMessage) error {
	e.mu.Lock()
	if e.running >= e.maxConcurrent {
		e.mu.Unlock()
		return fmt.Errorf("concurrency limit reached (%d/%d)", e.running, e.maxConcurrent)
	}
	e.running++
	e.totalTriggered++
	runID := e.totalTriggered
	e.mu.Unlock()

	go e.executeEvent(runID, event)
	return nil
}

// Stats returns current event scheduler statistics.
func (e *EventScheduler) Stats() map[string]int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return map[string]int{
		"running":   e.running,
		"triggered": e.totalTriggered,
		"success":   e.totalSuccess,
		"failed":    e.totalFailed,
	}
}

func (e *EventScheduler) executeEvent(runID int, event json.RawMessage) {
	defer func() {
		e.mu.Lock()
		e.running--
		e.mu.Unlock()
	}()

	ctx := e.ctx
	if ctx.Err() != nil {
		return
	}

	containerName := fmt.Sprintf("plugger-%s-evt-%d", e.plugin.Name, runID)
	slog.Info("event triggered", "plugin", e.plugin.Name, "run", runID)

	// Build env with event payload injected
	overrides := make(map[string]string)
	for k, v := range e.plugin.EnvOverrides {
		overrides[k] = v
	}
	overrides["PLUGGER_EVENT_PAYLOAD"] = string(event)

	// Create a temporary plugin copy for env building
	tmpPlugin := *e.plugin
	tmpPlugin.EnvOverrides = overrides
	env := tmpPlugin.BuildEnv(e.deps.Config.PCE)

	labels := map[string]string{
		ct.LabelManaged: "true",
		ct.LabelPlugin:  e.plugin.Name,
		ct.LabelMode:    "event",
	}

	var memory int64
	var cpus string
	if e.plugin.Manifest.Resources != nil {
		memory = lifecycle.ParseMemory(e.plugin.Manifest.Resources.MemoryLimit)
		cpus = e.plugin.Manifest.Resources.CPULimit
	}

	_ = e.deps.Runtime.Remove(ctx, containerName)

	containerID, err := e.deps.Runtime.Create(ctx, ct.CreateOpts{
		Name:    containerName,
		Image:   e.plugin.Manifest.Image,
		Env:     env,
		Network: e.deps.Config.Plugger.Network,
		Labels:  labels,
		Memory:  memory,
		CPUs:    cpus,
	})
	if err != nil {
		slog.Error("event: create failed", "plugin", e.plugin.Name, "run", runID, "error", err)
		e.mu.Lock()
		e.totalFailed++
		e.mu.Unlock()
		return
	}

	if err := e.deps.Runtime.Start(ctx, containerID); err != nil {
		slog.Error("event: start failed", "plugin", e.plugin.Name, "run", runID, "error", err)
		_ = e.deps.Runtime.Remove(ctx, containerID)
		e.mu.Lock()
		e.totalFailed++
		e.mu.Unlock()
		return
	}

	// Wait for exit
	waitCh, err := e.deps.Runtime.Wait(ctx, containerID)
	if err == nil {
		select {
		case <-ctx.Done():
		case result := <-waitCh:
			if result.StatusCode == 0 {
				slog.Info("event completed", "plugin", e.plugin.Name, "run", runID)
				e.mu.Lock()
				e.totalSuccess++
				e.mu.Unlock()
			} else {
				slog.Warn("event exited non-zero", "plugin", e.plugin.Name, "run", runID, "exitCode", result.StatusCode)
				e.mu.Lock()
				e.totalFailed++
				e.mu.Unlock()
			}
		}
	}

	_ = e.deps.Runtime.Remove(ctx, containerID)
}
