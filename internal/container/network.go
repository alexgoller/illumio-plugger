package container

import (
	"context"
	"fmt"
	"log/slog"
)

// SetupNetwork ensures the plugger Docker network exists.
func SetupNetwork(ctx context.Context, rt Runtime, name string) error {
	slog.Info("ensuring network exists", "network", name)
	if err := rt.EnsureNetwork(ctx, name); err != nil {
		return fmt.Errorf("setting up network %s: %w", name, err)
	}
	return nil
}
