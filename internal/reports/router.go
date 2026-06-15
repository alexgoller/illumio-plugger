package reports

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/robfig/cron/v3"
)

const maxRecentReports = 200

type outputEntry struct {
	output Output
	config config.OutputConfig
}

// Router accepts reports from plugins and dispatches to configured outputs.
type Router struct {
	mu      sync.RWMutex
	outputs []outputEntry
	recent  []ReportRecord
	cron    *cron.Cron

	aggMu  sync.Mutex
	aggBuf map[string][]*Report
}

// NewRouter creates a router from the configured outputs.
func NewRouter(outputs []config.OutputConfig) (*Router, error) {
	r := &Router{
		recent: make([]ReportRecord, 0, maxRecentReports),
		cron:   cron.New(),
		aggBuf: make(map[string][]*Report),
	}

	for _, cfg := range outputs {
		if !cfg.IsEnabled() {
			slog.Info("output disabled, skipping", "name", cfg.Name)
			continue
		}
		out, err := newOutput(cfg)
		if err != nil {
			slog.Warn("skipping output", "name", cfg.Name, "error", err)
			continue
		}
		r.outputs = append(r.outputs, outputEntry{output: out, config: cfg})
		slog.Info("output registered", "name", cfg.Name, "type", cfg.Type,
			"dryRun", cfg.DryRun, "aggregate", cfg.Aggregate)

		if cfg.Aggregate && cfg.Schedule != "" {
			name := cfg.Name
			_, err := r.cron.AddFunc(cfg.Schedule, func() { r.flushAggregate(name) })
			if err != nil {
				slog.Warn("invalid cron schedule for output", "name", name, "schedule", cfg.Schedule, "error", err)
			}
		}
	}

	r.cron.Start()
	return r, nil
}

// Publish accepts a report and routes it to matching outputs.
func (r *Router) Publish(report *Report) {
	if report.ID == "" {
		b := make([]byte, 8)
		rand.Read(b)
		report.ID = hex.EncodeToString(b)
	}
	if report.CreatedAt.IsZero() {
		report.CreatedAt = time.Now()
	}

	record := ReportRecord{Report: *report}

	for _, entry := range r.outputs {
		if !matchesFilter(entry.config.Filter, report) {
			record.Deliveries = append(record.Deliveries, DeliveryStatus{
				OutputName: entry.config.Name,
				OutputType: entry.config.Type,
				Status:     "filtered",
			})
			continue
		}

		if entry.config.DryRun {
			slog.Info("report dry-run",
				"output", entry.config.Name,
				"plugin", report.Plugin,
				"title", report.Title,
				"severity", report.Severity)
			record.Deliveries = append(record.Deliveries, DeliveryStatus{
				OutputName: entry.config.Name,
				OutputType: entry.config.Type,
				Status:     "dry_run",
			})
			continue
		}

		if entry.config.Aggregate {
			r.aggMu.Lock()
			r.aggBuf[entry.config.Name] = append(r.aggBuf[entry.config.Name], report)
			r.aggMu.Unlock()
			record.Deliveries = append(record.Deliveries, DeliveryStatus{
				OutputName: entry.config.Name,
				OutputType: entry.config.Type,
				Status:     "pending",
			})
			continue
		}

		go r.sendWithRetry(entry, report)
		record.Deliveries = append(record.Deliveries, DeliveryStatus{
			OutputName: entry.config.Name,
			OutputType: entry.config.Type,
			Status:     "delivering",
		})
	}

	r.addRecent(record)

	slog.Info("report published",
		"id", report.ID,
		"plugin", report.Plugin,
		"title", report.Title,
		"outputs", len(r.outputs))
}

// Stop shuts down the cron scheduler and flushes remaining aggregates.
func (r *Router) Stop() {
	ctx := r.cron.Stop()
	<-ctx.Done()
	for _, entry := range r.outputs {
		if entry.config.Aggregate {
			r.flushAggregate(entry.config.Name)
		}
	}
}

// RecentReports returns the most recent report records.
func (r *Router) RecentReports() []ReportRecord {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ReportRecord, len(r.recent))
	copy(out, r.recent)
	return out
}

// OutputCount returns the number of active outputs.
func (r *Router) OutputCount() int {
	return len(r.outputs)
}

// OutputStats returns detailed stats per output including delivery counts.
type OutputStat struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	DryRun    bool   `json:"dry_run"`
	Delivered int    `json:"delivered"`
	Failed    int    `json:"failed"`
	Filtered  int    `json:"filtered"`
	Pending   int    `json:"pending"`
	Healthy   bool   `json:"healthy"`
	LastError string `json:"last_error,omitempty"`
}

func (r *Router) Stats() []OutputStat {
	r.mu.RLock()
	recent := r.recent
	r.mu.RUnlock()

	statMap := make(map[string]*OutputStat)
	for _, e := range r.outputs {
		statMap[e.config.Name] = &OutputStat{
			Name:    e.config.Name,
			Type:    e.config.Type,
			DryRun:  e.config.DryRun,
			Healthy: true,
		}
	}

	for _, rec := range recent {
		for _, d := range rec.Deliveries {
			s, ok := statMap[d.OutputName]
			if !ok {
				continue
			}
			switch d.Status {
			case "delivered", "dry_run":
				s.Delivered++
			case "failed":
				s.Failed++
				s.Healthy = false
				if d.Error != "" {
					s.LastError = d.Error
				}
			case "filtered":
				s.Filtered++
			case "pending", "delivering":
				s.Pending++
			}
		}
	}

	var stats []OutputStat
	for _, e := range r.outputs {
		stats = append(stats, *statMap[e.config.Name])
	}
	return stats
}

// TestOutput sends a test report to a specific named output, bypassing filters.
func (r *Router) TestOutput(name string) error {
	var entry *outputEntry
	for i := range r.outputs {
		if r.outputs[i].config.Name == name {
			entry = &r.outputs[i]
			break
		}
	}
	if entry == nil {
		return fmt.Errorf("output %q not found", name)
	}

	testReport := &Report{
		ID:        "test-" + name,
		Plugin:    "plugger",
		Title:     "Test message from Plugger",
		Severity:  SeverityInfo,
		Body:      fmt.Sprintf("This is a test message for output channel **%s** (%s).\n\nIf you see this, the output is configured correctly.", name, entry.config.Type),
		Tags:      []string{"test"},
		CreatedAt: time.Now(),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	err := entry.output.Send(ctx, testReport)

	record := ReportRecord{
		Report: *testReport,
		Deliveries: []DeliveryStatus{{
			OutputName: name,
			OutputType: entry.config.Type,
		}},
	}

	if err != nil {
		record.Deliveries[0].Status = "failed"
		record.Deliveries[0].Error = err.Error()
		slog.Error("test message failed", "output", name, "error", err)
	} else {
		now := time.Now()
		record.Deliveries[0].Status = "delivered"
		record.Deliveries[0].DeliveredAt = &now
		slog.Info("test message sent", "output", name)
	}

	r.addRecent(record)
	return err
}

// OutputNames returns the names of all configured outputs.
func (r *Router) OutputNames() []string {
	var names []string
	for _, e := range r.outputs {
		names = append(names, e.config.Name)
	}
	return names
}

func (r *Router) addRecent(record ReportRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.recent = append([]ReportRecord{record}, r.recent...)
	if len(r.recent) > maxRecentReports {
		r.recent = r.recent[:maxRecentReports]
	}
}

func (r *Router) sendWithRetry(entry outputEntry, report *Report) {
	maxRetries := 3
	backoff := 2 * time.Second
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		lastErr = entry.output.Send(ctx, report)
		cancel()

		if lastErr == nil {
			slog.Info("report delivered",
				"output", entry.config.Name,
				"plugin", report.Plugin,
				"title", report.Title,
				"attempts", attempt)
			return
		}

		slog.Warn("report delivery failed, retrying",
			"output", entry.config.Name,
			"attempt", attempt,
			"error", lastErr)

		if attempt < maxRetries {
			time.Sleep(backoff)
			backoff *= 2
		}
	}

	slog.Error("report delivery failed permanently",
		"output", entry.config.Name,
		"plugin", report.Plugin,
		"title", report.Title,
		"error", lastErr)
}

func (r *Router) flushAggregate(outputName string) {
	r.aggMu.Lock()
	buf := r.aggBuf[outputName]
	r.aggBuf[outputName] = nil
	r.aggMu.Unlock()

	if len(buf) == 0 {
		return
	}

	var out Output
	for _, entry := range r.outputs {
		if entry.config.Name == outputName {
			out = entry.output
			break
		}
	}
	if out == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := out.SendBatch(ctx, buf); err != nil {
		slog.Error("aggregate delivery failed",
			"output", outputName,
			"reports", len(buf),
			"error", err)
	} else {
		slog.Info("aggregate delivered",
			"output", outputName,
			"reports", len(buf))
	}
}

func matchesFilter(f config.OutputFilter, report *Report) bool {
	if len(f.Severity) > 0 {
		found := false
		for _, s := range f.Severity {
			if s == report.Severity {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.Plugins) > 0 {
		found := false
		for _, p := range f.Plugins {
			if p == report.Plugin {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if len(f.Tags) > 0 {
		found := false
		for _, ft := range f.Tags {
			for _, rt := range report.Tags {
				if ft == rt {
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func newOutput(cfg config.OutputConfig) (Output, error) {
	switch cfg.Type {
	case "slack":
		return NewSlackOutput(cfg)
	case "teams":
		return NewTeamsOutput(cfg)
	case "email":
		return NewEmailOutput(cfg)
	case "webhook":
		return NewWebhookOutput(cfg)
	default:
		return nil, fmt.Errorf("unknown output type: %s", cfg.Type)
	}
}
