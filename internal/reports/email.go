package reports

import (
	"context"
	"fmt"
	"net/smtp"
	"os"
	"strings"

	"github.com/illumio/plugger/internal/config"
)

// EmailOutput sends reports via SMTP.
type EmailOutput struct {
	name     string
	host     string
	port     int
	user     string
	password string
	from     string
	to       []string
}

func NewEmailOutput(cfg config.OutputConfig) (*EmailOutput, error) {
	if cfg.SMTPHost == "" {
		return nil, fmt.Errorf("email output %q: smtpHost required", cfg.Name)
	}
	if len(cfg.To) == 0 {
		return nil, fmt.Errorf("email output %q: to addresses required", cfg.Name)
	}

	password := ""
	if cfg.SMTPPasswordEnv != "" {
		password = os.Getenv(cfg.SMTPPasswordEnv)
	}

	from := cfg.From
	if from == "" {
		from = cfg.SMTPUser
	}
	if from == "" {
		from = "plugger@localhost"
	}

	port := cfg.SMTPPort
	if port == 0 {
		port = 587
	}

	return &EmailOutput{
		name: cfg.Name, host: cfg.SMTPHost, port: port,
		user: cfg.SMTPUser, password: password,
		from: from, to: cfg.To,
	}, nil
}

func (e *EmailOutput) Name() string { return e.name }
func (e *EmailOutput) Type() string { return "email" }

func (e *EmailOutput) Send(_ context.Context, report *Report) error {
	subject := fmt.Sprintf("[Plugger/%s] %s: %s",
		report.Plugin, strings.ToUpper(report.Severity), report.Title)
	body := renderEmailHTML([]*Report{report})
	return e.sendMail(subject, body)
}

func (e *EmailOutput) SendBatch(_ context.Context, reports []*Report) error {
	subject := fmt.Sprintf("[Plugger] Report Digest — %d reports", len(reports))
	body := renderEmailHTML(reports)
	return e.sendMail(subject, body)
}

func (e *EmailOutput) sendMail(subject, htmlBody string) error {
	addr := fmt.Sprintf("%s:%d", e.host, e.port)

	headers := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		e.from, strings.Join(e.to, ", "), subject)

	msg := []byte(headers + htmlBody)

	var auth smtp.Auth
	if e.user != "" && e.password != "" {
		auth = smtp.PlainAuth("", e.user, e.password, e.host)
	}

	return smtp.SendMail(addr, auth, e.from, e.to, msg)
}

func renderEmailHTML(reports []*Report) string {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html><head><meta charset="utf-8"></head>
<body style="background:#1e1e2e;color:#cdd6f4;font-family:system-ui,sans-serif;padding:20px;">
<div style="max-width:700px;margin:0 auto;">
<h1 style="color:#89b4fa;border-bottom:2px solid #313244;padding-bottom:10px;">Plugger Report</h1>`)

	for _, r := range reports {
		color := "#a6e3a1"
		if r.Severity == SeverityWarning {
			color = "#f9e2af"
		} else if r.Severity == SeverityCritical {
			color = "#f38ba8"
		}

		sb.WriteString(fmt.Sprintf(`
<div style="background:#11111b;border:1px solid #313244;border-radius:8px;padding:16px;margin:12px 0;">
  <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
    <span style="background:%s;color:#11111b;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:600;">%s</span>
    <strong style="color:#cdd6f4;font-size:16px;">%s</strong>
  </div>
  <div style="color:#6c7086;font-size:12px;margin-bottom:8px;">Plugin: %s · %s</div>
  <div style="color:#bac2de;font-size:14px;line-height:1.6;white-space:pre-wrap;">%s</div>`,
			color, strings.ToUpper(r.Severity), r.Title,
			r.Plugin, r.CreatedAt.Format("2006-01-02 15:04 MST"),
			r.Body))

		if len(r.Tags) > 0 {
			sb.WriteString(fmt.Sprintf(`
  <div style="margin-top:8px;color:#6c7086;font-size:11px;">Tags: %s</div>`,
				strings.Join(r.Tags, ", ")))
		}

		sb.WriteString("\n</div>")
	}

	sb.WriteString(`
<div style="color:#585b70;font-size:11px;margin-top:20px;text-align:center;">
  Sent by Plugger — Plugin Framework for Illumio PCE
</div>
</div></body></html>`)

	return sb.String()
}
