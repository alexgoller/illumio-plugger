package reports

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/illumio/plugger/internal/config"
)

// WebhookOutput sends reports as JSON to a generic HTTP endpoint.
type WebhookOutput struct {
	name    string
	url     string
	method  string
	headers map[string]string
}

func NewWebhookOutput(cfg config.OutputConfig) (*WebhookOutput, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("webhook output %q: url required", cfg.Name)
	}
	method := cfg.Method
	if method == "" {
		method = "POST"
	}

	headers := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headers[k] = os.Expand(v, os.Getenv)
	}

	return &WebhookOutput{name: cfg.Name, url: cfg.URL, method: method, headers: headers}, nil
}

func (w *WebhookOutput) Name() string { return w.name }
func (w *WebhookOutput) Type() string { return "webhook" }

func (w *WebhookOutput) Send(ctx context.Context, report *Report) error {
	return w.post(ctx, report)
}

func (w *WebhookOutput) SendBatch(ctx context.Context, reports []*Report) error {
	return w.post(ctx, map[string]any{"reports": reports, "count": len(reports)})
}

func (w *WebhookOutput) post(ctx context.Context, payload any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, w.method, w.url, bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for k, v := range w.headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("webhook %s: %w", w.name, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook %s returned %d", w.name, resp.StatusCode)
	}
	return nil
}
