// Package scheduler manages plugin container lifecycles according to their scheduling mode.
package scheduler

import "context"

// Scheduler manages the lifecycle of a single plugin.
type Scheduler interface {
	// Start begins scheduling the plugin.
	Start(ctx context.Context) error
	// Stop gracefully stops the scheduler and its managed container.
	Stop(ctx context.Context) error
	// Name returns the plugin name.
	Name() string
}
