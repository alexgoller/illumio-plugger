// Package health provides HTTP health checking for running plugin containers.
package health

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// OnFailure is called when consecutive health check failures exceed the threshold.
type OnFailure func(pluginName string, lastErr error)

// Checker performs periodic HTTP health checks against a plugin container.
type Checker struct {
	pluginName string
	url        string
	interval   time.Duration
	timeout    time.Duration
	retries    int
	onFailure  OnFailure

	cancel           context.CancelFunc
	done             chan struct{}
	consecutiveFails int
}

// NewChecker creates a health checker for a plugin.
// url should be the full health check URL, e.g. http://localhost:12345/healthz
func NewChecker(pluginName, url string, interval, timeout time.Duration, retries int, onFailure OnFailure) *Checker {
	if interval == 0 {
		interval = 30 * time.Second
	}
	if timeout == 0 {
		timeout = 5 * time.Second
	}
	if retries == 0 {
		retries = 3
	}
	return &Checker{
		pluginName: pluginName,
		url:        url,
		interval:   interval,
		timeout:    timeout,
		retries:    retries,
		onFailure:  onFailure,
		done:       make(chan struct{}),
	}
}

// Start begins health checking in a background goroutine.
func (c *Checker) Start(ctx context.Context) {
	ctx, c.cancel = context.WithCancel(ctx)
	go c.loop(ctx)
}

// Stop stops the health checker.
func (c *Checker) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	<-c.done
}

func (c *Checker) loop(ctx context.Context) {
	defer close(c.done)

	// Wait a bit before first check to let the container start
	select {
	case <-ctx.Done():
		return
	case <-time.After(c.interval):
	}

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			err := c.check(ctx)
			if err != nil {
				c.consecutiveFails++
				slog.Debug("health check failed", "plugin", c.pluginName,
					"error", err, "consecutive", c.consecutiveFails, "threshold", c.retries)

				if c.consecutiveFails >= c.retries {
					slog.Warn("health check threshold exceeded",
						"plugin", c.pluginName, "failures", c.consecutiveFails)
					if c.onFailure != nil {
						c.onFailure(c.pluginName, err)
					}
					c.consecutiveFails = 0
				}
			} else {
				if c.consecutiveFails > 0 {
					slog.Debug("health check recovered", "plugin", c.pluginName)
				}
				c.consecutiveFails = 0
			}
		}
	}
}

func (c *Checker) check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", c.url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unhealthy: HTTP %d", resp.StatusCode)
	}

	return nil
}
