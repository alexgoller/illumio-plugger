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
		h.json(w, http.StatusOK, map[string]any{"outputs": 0})
		return
	}
	h.json(w, http.StatusOK, map[string]any{
		"outputs":     h.reports.OutputCount(),
		"output_list": h.reports.Stats(),
		"recent":      len(h.reports.RecentReports()),
	})
}

func (h *Handler) handleReportsPage(w http.ResponseWriter, r *http.Request) {
	var recentReports []reports.ReportRecord
	var outputCount int
	if h.reports != nil {
		recentReports = h.reports.RecentReports()
		outputCount = h.reports.OutputCount()
	}

	data := map[string]any{
		"Reports":     recentReports,
		"OutputCount": outputCount,
	}
	h.render(w, "layout.html", "reports.html", data)
}
