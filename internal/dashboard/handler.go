package dashboard

import (
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/reports"
)

// Handler serves the dashboard web UI and API.
type Handler struct {
	deps    *lifecycle.Deps
	logger  *slog.Logger
	tmpl    *template.Template
	events  *EventRegistry
	reports *reports.Router
}

// NewHandler creates a new dashboard handler.
func NewHandler(store *plugin.Store, rt container.Runtime, cfg *config.Config, logger *slog.Logger) *Handler {
	return &Handler{
		deps: &lifecycle.Deps{
			Store:   store,
			Runtime: rt,
			Config:  cfg,
		},
		logger: logger,
		tmpl:   parseTemplates(),
	}
}

// SetEventRegistry attaches the event registry to the handler for webhook support.
func (h *Handler) SetEventRegistry(r *EventRegistry) {
	h.events = r
}

// SetReportRouter attaches the report routing system.
func (h *Handler) SetReportRouter(r *reports.Router) {
	h.reports = r
}

// Routes returns the HTTP mux with all dashboard routes registered.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	// Static assets
	mux.HandleFunc("GET /logo.png", h.handleLogo)
	mux.HandleFunc("GET /logo.svg", h.handleLogoSVG)

	// Customer branding assets
	brandDir := filepath.Join(h.deps.Config.Plugger.DataDir, "brand")
	mux.Handle("/brand/", http.StripPrefix("/brand/", http.FileServer(http.Dir(brandDir))))

	// HTML pages
	mux.HandleFunc("GET /{$}", h.handleIndex)
	mux.HandleFunc("GET /plugins/{name}", h.handlePluginDetail)

	// JSON API
	mux.HandleFunc("GET /api/plugins", h.handleAPIListPlugins)
	mux.HandleFunc("GET /api/plugins/{name}", h.handleAPIGetPlugin)

	// Actions (return HTML fragments for htmx)
	mux.HandleFunc("POST /api/plugins/{name}/start", h.handleStartPlugin)
	mux.HandleFunc("POST /api/plugins/{name}/stop", h.handleStopPlugin)
	mux.HandleFunc("POST /api/plugins/{name}/restart", h.handleRestartPlugin)
	mux.HandleFunc("POST /api/plugins/{name}/uninstall", h.handleUninstallPlugin)

	// Config editing (per-plugin)
	mux.HandleFunc("POST /api/plugins/{name}/config", h.handleSaveConfig)

	// Unified config page (all plugins)
	mux.HandleFunc("GET /config", h.handleConfigAll)
	mux.HandleFunc("POST /config", h.handleSaveConfigAll)

	// SSE log stream
	mux.HandleFunc("GET /api/plugins/{name}/logs", h.handleLogs)

	// Log download for issue filing
	mux.HandleFunc("GET /api/plugins/{name}/logs/download", h.handleLogDownload)

	// Registry
	mux.HandleFunc("GET /registry", h.handleRegistryPage)
	mux.HandleFunc("GET /api/registry", h.handleAPIRegistry)
	mux.HandleFunc("POST /api/registry/install", h.handleAPIRegistryInstall)

	// Reports
	mux.HandleFunc("POST /api/reports/publish", h.handleReportPublish)
	mux.HandleFunc("POST /api/reports/test/{name}", h.handleReportTest)
	mux.HandleFunc("GET /api/reports", h.handleReportList)
	mux.HandleFunc("GET /api/reports/stats", h.handleReportStats)
	mux.HandleFunc("GET /reports", h.handleReportsPage)
	mux.HandleFunc("POST /api/outputs/add", h.handleOutputAdd)
	mux.HandleFunc("DELETE /api/outputs/{name}", h.handleOutputRemove)

	// Update check
	mux.HandleFunc("GET /api/plugins/updates", h.handleCheckUpdates)
	mux.HandleFunc("POST /api/plugins/{name}/update", h.handleUpdatePlugin)

	// Event webhook
	mux.HandleFunc("POST /api/events/trigger", h.handleEventTrigger)
	mux.HandleFunc("GET /api/events/stats", h.handleEventStats)

	// Reverse proxy to plugin UIs — handle all HTTP methods
	mux.Handle("/plugins/{name}/ui/", http.HandlerFunc(h.handlePluginProxy))

	// Health check — always unauthenticated
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	})

	return mux
}

// WrappedRoutes returns the route handler wrapped with auth middleware if enabled.
// Callers should use this instead of Routes() to get the fully configured handler.
func (h *Handler) WrappedRoutes() http.Handler {
	mux := h.Routes()

	if h.deps.Config.Plugger.Auth.Enabled {
		auth := NewAuthMiddleware(&h.deps.Config.Plugger.Auth)
		mux.HandleFunc("GET /login", auth.HandleLogin)
		mux.HandleFunc("POST /login", auth.HandleLogin)
		mux.HandleFunc("POST /api/auth/logout", auth.HandleLogout)
		return auth.Wrap(mux)
	}

	return mux
}

// handleIndex renders the plugin list page.
func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.serverError(w, "listing plugins", err)
		return
	}

	data := map[string]any{
		"Plugins": plugins,
	}

	h.render(w, "layout.html", "plugins.html", data)
}

// handlePluginDetail renders the plugin detail page.
func (h *Handler) handlePluginDetail(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// If fragment=status, return just the status fragment for htmx polling
	if r.URL.Query().Get("fragment") == "status" {
		t, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/plugin_detail.html")
		if err == nil {
			t.ExecuteTemplate(w, "plugin_status_fragment", p)
		}
		return
	}

	// Fetch README — try homepage first, fallback to well-known GitHub path
	readmeContent := ""
	homepage := ""
	if p.Metadata != nil && p.Metadata.Info != nil {
		homepage = p.Metadata.Info.Homepage
	}
	if homepage == "" {
		homepage = "https://github.com/alexgoller/illumio-plugger/tree/main/" + name
	}
	readmeContent = fetchReadme(name, homepage)

	data := map[string]any{
		"Plugin": p,
		"Readme": readmeContent,
	}

	h.render(w, "layout.html", "plugin_detail.html", data)
}

// handleAPIListPlugins returns JSON list of all plugins.
func (h *Handler) handleAPIListPlugins(w http.ResponseWriter, r *http.Request) {
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.serverError(w, "listing plugins", err)
		return
	}
	h.json(w, http.StatusOK, plugins)
}

// handleAPIGetPlugin returns JSON detail of a single plugin.
func (h *Handler) handleAPIGetPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h.json(w, http.StatusOK, p)
}

// render parses and executes templates fresh for each request.
func (h *Handler) render(w http.ResponseWriter, layout, page string, data any) {
	t, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/"+layout, "templates/"+page, "templates/plugin_row.html", "templates/plugin_config.html")
	if err != nil {
		h.serverError(w, "parsing templates", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, layout, data); err != nil {
		h.logger.Error("rendering template", "error", err)
	}
}

func (h *Handler) json(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// fetchReadme tries to get the plugin README from GitHub.
func fetchReadme(name, homepage string) string {
	// Convert GitHub tree URL to raw URL
	// https://github.com/alexgoller/illumio-plugger/tree/main/pce-health-monitor
	// → https://raw.githubusercontent.com/alexgoller/illumio-plugger/main/pce-health-monitor/README.md
	rawURL := ""
	if strings.Contains(homepage, "github.com") && strings.Contains(homepage, "/tree/") {
		rawURL = strings.Replace(homepage, "github.com", "raw.githubusercontent.com", 1)
		rawURL = strings.Replace(rawURL, "/tree/", "/", 1)
		rawURL += "/README.md"
	}
	if rawURL == "" {
		return ""
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(rawURL)
	if err != nil || resp.StatusCode != 200 {
		return ""
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	return string(data)
}

func (h *Handler) serverError(w http.ResponseWriter, action string, err error) {
	h.logger.Error(action, "error", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
