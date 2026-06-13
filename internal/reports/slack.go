package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/illumio/plugger/internal/config"
)

// SlackOutput sends reports to a Slack incoming webhook.
type SlackOutput struct {
	name    string
	webhook string
}

func NewSlackOutput(cfg config.OutputConfig) (*SlackOutput, error) {
	if cfg.Webhook == "" {
		return nil, fmt.Errorf("slack output %q: webhook URL required", cfg.Name)
	}
	return &SlackOutput{name: cfg.Name, webhook: cfg.Webhook}, nil
}

func (s *SlackOutput) Name() string { return s.name }
func (s *SlackOutput) Type() string { return "slack" }

func (s *SlackOutput) Send(ctx context.Context, report *Report) error {
	payload := buildSlackPayload(report)
	return s.post(ctx, payload)
}

func (s *SlackOutput) SendBatch(ctx context.Context, reports []*Report) error {
	payload := buildSlackBatchPayload(reports)
	return s.post(ctx, payload)
}

func (s *SlackOutput) post(ctx context.Context, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", s.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("slack webhook returned %d", resp.StatusCode)
	}
	return nil
}

func severityEmoji(s string) string {
	switch s {
	case SeverityCritical:
		return "\U0001f6a8" // rotating light
	case SeverityWarning:
		return "⚠️" // warning
	default:
		return "\U0001f4d8" // blue book
	}
}

func buildSlackPayload(r *Report) map[string]any {
	header := fmt.Sprintf("%s *%s*", severityEmoji(r.Severity), r.Title)
	meta := fmt.Sprintf("Plugin: `%s` | Severity: `%s` | %s",
		r.Plugin, r.Severity, r.CreatedAt.Format("15:04:05 MST"))

	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{"type": "plain_text", "text": r.Title}},
		{"type": "section", "text": map[string]any{"type": "mrkdwn", "text": header}},
		{"type": "context", "elements": []map[string]any{
			{"type": "mrkdwn", "text": meta},
		}},
	}

	if r.Body != "" {
		body := r.Body
		if len(body) > 2900 {
			body = body[:2900] + "\n_(truncated)_"
		}
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": body},
		})
	}

	if len(r.Tags) > 0 {
		tags := "Tags: " + strings.Join(r.Tags, ", ")
		blocks = append(blocks, map[string]any{
			"type": "context",
			"elements": []map[string]any{
				{"type": "mrkdwn", "text": tags},
			},
		})
	}

	return map[string]any{"blocks": blocks}
}

func buildSlackBatchPayload(reports []*Report) map[string]any {
	blocks := []map[string]any{
		{"type": "header", "text": map[string]any{
			"type": "plain_text",
			"text": fmt.Sprintf("Plugger Report Digest (%d reports)", len(reports)),
		}},
	}

	for i, r := range reports {
		if i > 0 {
			blocks = append(blocks, map[string]any{"type": "divider"})
		}
		entry := fmt.Sprintf("%s *%s* — `%s`\n%s",
			severityEmoji(r.Severity), r.Title, r.Plugin, truncate(r.Body, 500))
		blocks = append(blocks, map[string]any{
			"type": "section",
			"text": map[string]any{"type": "mrkdwn", "text": entry},
		})
		if len(blocks) > 45 {
			blocks = append(blocks, map[string]any{
				"type": "section",
				"text": map[string]any{"type": "mrkdwn", "text": fmt.Sprintf("_...and %d more reports_", len(reports)-i-1)},
			})
			break
		}
	}

	return map[string]any{"blocks": blocks}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
