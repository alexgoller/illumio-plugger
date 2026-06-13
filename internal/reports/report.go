package reports

import (
	"fmt"
	"time"
)

const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Report is the payload submitted by a plugin via POST /api/reports/publish.
type Report struct {
	ID        string         `json:"id"`
	Plugin    string         `json:"plugin"`
	Title     string         `json:"title"`
	Severity  string         `json:"severity"`
	Body      string         `json:"body"`
	Tags      []string       `json:"tags,omitempty"`
	Data      map[string]any `json:"data,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

// DeliveryStatus tracks delivery of a report to a single output.
type DeliveryStatus struct {
	OutputName  string     `json:"output_name"`
	OutputType  string     `json:"output_type"`
	Status      string     `json:"status"` // delivered, failed, filtered, dry_run, pending
	Error       string     `json:"error,omitempty"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	Attempts    int        `json:"attempts"`
}

// ReportRecord is a report plus its delivery statuses.
type ReportRecord struct {
	Report     Report           `json:"report"`
	Deliveries []DeliveryStatus `json:"deliveries"`
}

// Validate checks minimum required fields.
func (r *Report) Validate() error {
	if r.Plugin == "" {
		return fmt.Errorf("plugin is required")
	}
	if r.Title == "" {
		return fmt.Errorf("title is required")
	}
	if r.Severity == "" {
		r.Severity = SeverityInfo
	}
	switch r.Severity {
	case SeverityInfo, SeverityWarning, SeverityCritical:
	default:
		return fmt.Errorf("severity must be info, warning, or critical")
	}
	return nil
}
