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

// TeamsOutput sends reports to a Microsoft Teams incoming webhook.
type TeamsOutput struct {
	name    string
	webhook string
}

func NewTeamsOutput(cfg config.OutputConfig) (*TeamsOutput, error) {
	if cfg.Webhook == "" {
		return nil, fmt.Errorf("teams output %q: webhook URL required", cfg.Name)
	}
	return &TeamsOutput{name: cfg.Name, webhook: cfg.Webhook}, nil
}

func (t *TeamsOutput) Name() string { return t.name }
func (t *TeamsOutput) Type() string { return "teams" }

func (t *TeamsOutput) Send(ctx context.Context, report *Report) error {
	card := buildTeamsCard(report)
	return t.post(ctx, card)
}

func (t *TeamsOutput) SendBatch(ctx context.Context, reports []*Report) error {
	card := buildTeamsBatchCard(reports)
	return t.post(ctx, card)
}

func (t *TeamsOutput) post(ctx context.Context, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "POST", t.webhook, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("teams webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("teams webhook returned %d", resp.StatusCode)
	}
	return nil
}

func severityColor(s string) string {
	switch s {
	case SeverityCritical:
		return "attention"
	case SeverityWarning:
		return "warning"
	default:
		return "good"
	}
}

func severityHex(s string) string {
	switch s {
	case SeverityCritical:
		return "#f38ba8"
	case SeverityWarning:
		return "#f9e2af"
	default:
		return "#a6e3a1"
	}
}

func buildTeamsCard(r *Report) map[string]any {
	facts := []map[string]any{
		{"title": "Plugin", "value": r.Plugin},
		{"title": "Severity", "value": strings.ToUpper(r.Severity)},
		{"title": "Time", "value": r.CreatedAt.Format("15:04:05 MST")},
	}
	if len(r.Tags) > 0 {
		facts = append(facts, map[string]any{"title": "Tags", "value": strings.Join(r.Tags, ", ")})
	}

	bodyBlocks := []map[string]any{
		{
			"type":   "TextBlock",
			"text":   r.Title,
			"weight": "Bolder",
			"size":   "Medium",
			"color":  severityColor(r.Severity),
		},
		{
			"type": "FactSet",
			"facts": facts,
		},
	}

	if r.Body != "" {
		body := r.Body
		if len(body) > 2000 {
			body = body[:2000] + "\n_(truncated)_"
		}
		bodyBlocks = append(bodyBlocks, map[string]any{
			"type": "TextBlock",
			"text": body,
			"wrap": true,
			"size": "Small",
		})
	}

	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"msteams": map[string]any{
						"width": "Full",
					},
					"body": bodyBlocks,
				},
			},
		},
	}
}

func buildTeamsBatchCard(reports []*Report) map[string]any {
	bodyBlocks := []map[string]any{
		{
			"type":   "TextBlock",
			"text":   fmt.Sprintf("Plugger Report Digest — %d reports", len(reports)),
			"weight": "Bolder",
			"size":   "Medium",
		},
	}

	for i, r := range reports {
		if i > 0 {
			bodyBlocks = append(bodyBlocks, map[string]any{
				"type":      "TextBlock",
				"text":      "---",
				"separator": true,
			})
		}

		entry := fmt.Sprintf("**%s** — `%s` (%s)", r.Title, r.Plugin, strings.ToUpper(r.Severity))
		if r.Body != "" {
			body := r.Body
			if len(body) > 300 {
				body = body[:300] + "..."
			}
			entry += "\n\n" + body
		}

		bodyBlocks = append(bodyBlocks, map[string]any{
			"type":  "TextBlock",
			"text":  entry,
			"wrap":  true,
			"size":  "Small",
			"color": severityColor(r.Severity),
		})

		if len(bodyBlocks) > 30 {
			bodyBlocks = append(bodyBlocks, map[string]any{
				"type": "TextBlock",
				"text": fmt.Sprintf("_...and %d more reports_", len(reports)-i-1),
			})
			break
		}
	}

	return map[string]any{
		"type": "message",
		"attachments": []map[string]any{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]any{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"msteams": map[string]any{
						"width": "Full",
					},
					"body": bodyBlocks,
				},
			},
		},
	}
}
