package dashboard

import (
	"encoding/json"
	"io"
	"net/http"

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
	}
	h.render(w, "layout.html", "reports.html", data)
}
