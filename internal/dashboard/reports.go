package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/reports"
)

func (h *Handler) handleReportPublish(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		http.Error(w, "Report system not configured", http.StatusServiceUnavailable)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var report reports.Report
	if err := json.Unmarshal(body, &report); err != nil {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "Invalid JSON: " + err.Error()})
		return
	}

	if err := report.Validate(); err != nil {
		h.json(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	go h.reports.Publish(&report)

	h.json(w, http.StatusAccepted, map[string]string{
		"status": "accepted",
		"id":     report.ID,
	})
}

func (h *Handler) handleReportList(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		h.json(w, http.StatusOK, []reports.ReportRecord{})
		return
	}
	h.json(w, http.StatusOK, h.reports.RecentReports())
}

func (h *Handler) handleReportStats(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		h.json(w, http.StatusOK, map[string]any{"configured": false, "outputs": 0})
		return
	}
	h.json(w, http.StatusOK, map[string]any{
		"configured": true,
		"outputs":    h.reports.OutputCount(),
		"channels":   h.reports.Stats(),
		"recent":     len(h.reports.RecentReports()),
	})
}

func (h *Handler) handleReportTest(w http.ResponseWriter, r *http.Request) {
	if h.reports == nil {
		h.json(w, http.StatusServiceUnavailable, map[string]string{"error": "Report system not configured"})
		return
	}

	name := r.PathValue("name")
	if name == "" {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "output name required"})
		return
	}

	err := h.reports.TestOutput(name)
	if err != nil {
		h.json(w, http.StatusBadGateway, map[string]string{
			"status": "failed",
			"output": name,
			"error":  err.Error(),
		})
		return
	}

	h.json(w, http.StatusOK, map[string]string{
		"status": "delivered",
		"output": name,
	})
}

func (h *Handler) handleReportsPage(w http.ResponseWriter, r *http.Request) {
	var recentReports []reports.ReportRecord
	var outputStats []reports.OutputStat
	configured := false

	if h.reports != nil {
		recentReports = h.reports.RecentReports()
		outputStats = h.reports.Stats()
		configured = true
	}

	data := map[string]any{
		"Reports":    recentReports,
		"Outputs":    outputStats,
		"Configured": configured,
		"Message":    "",
	}
	h.render(w, "layout.html", "reports.html", data)
}

func (h *Handler) handleOutputAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "Invalid form"})
		return
	}

	name := r.FormValue("name")
	outputType := r.FormValue("type")
	if name == "" || outputType == "" {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "name and type are required"})
		return
	}

	o := config.OutputConfig{
		Name:   name,
		Type:   outputType,
		DryRun: r.FormValue("dry_run") == "true",
	}

	switch outputType {
	case "slack", "teams":
		o.Webhook = r.FormValue("webhook")
		if o.Webhook == "" {
			h.json(w, http.StatusBadRequest, map[string]string{"error": "webhook URL required"})
			return
		}
	case "email":
		o.SMTPHost = r.FormValue("smtp_host")
		o.SMTPUser = r.FormValue("smtp_user")
		o.SMTPPasswordEnv = r.FormValue("smtp_password_env")
		o.From = r.FormValue("from")
		if to := r.FormValue("to"); to != "" {
			for _, addr := range splitComma(to) {
				o.To = append(o.To, addr)
			}
		}
		o.Schedule = r.FormValue("schedule")
		o.Aggregate = r.FormValue("aggregate") == "true"
	case "webhook":
		o.URL = r.FormValue("url")
		o.Method = r.FormValue("method")
		if o.Method == "" {
			o.Method = "POST"
		}
		if o.URL == "" {
			h.json(w, http.StatusBadRequest, map[string]string{"error": "URL required for webhook"})
			return
		}
	}

	if sev := r.FormValue("severity"); sev != "" {
		o.Filter.Severity = splitComma(sev)
	}

	store := reports.NewOutputStore(h.deps.Config.Plugger.DataDir)
	if err := store.Add(o); err != nil {
		h.json(w, http.StatusConflict, map[string]string{"error": err.Error()})
		return
	}

	h.json(w, http.StatusOK, map[string]string{
		"status":  "added",
		"name":    name,
		"message": "Output added. Restart plugger to activate.",
	})
}

func (h *Handler) handleOutputRemove(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if name == "" {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}

	store := reports.NewOutputStore(h.deps.Config.Plugger.DataDir)
	if err := store.Remove(name); err != nil {
		h.json(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	h.json(w, http.StatusOK, map[string]string{
		"status":  "removed",
		"name":    name,
		"message": "Output removed. Restart plugger to apply.",
	})
}

func splitComma(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}
