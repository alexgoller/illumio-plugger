package dashboard

import (
	"encoding/json"
	"html/template"
	"log/slog"
	"net/http"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

// Handler serves the dashboard web UI and API.
type Handler struct {
	deps   *lifecycle.Deps
	logger *slog.Logger
	tmpl   *template.Template
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

// Routes returns the HTTP mux with all dashboard routes registered.
func (h *Handler) Routes() *http.ServeMux {
	mux := http.NewServeMux()

	// HTML pages
	mux.HandleFunc("GET /", h.handleIndex)
	mux.HandleFunc("GET /plugins/{name}", h.handlePluginDetail)

	// JSON API
	mux.HandleFunc("GET /api/plugins", h.handleAPIListPlugins)
	mux.HandleFunc("GET /api/plugins/{name}", h.handleAPIGetPlugin)

	// Actions (return HTML fragments for htmx)
	mux.HandleFunc("POST /api/plugins/{name}/start", h.handleStartPlugin)
	mux.HandleFunc("POST /api/plugins/{name}/stop", h.handleStopPlugin)
	mux.HandleFunc("POST /api/plugins/{name}/restart", h.handleRestartPlugin)

	// SSE log stream
	mux.HandleFunc("GET /api/plugins/{name}/logs", h.handleLogs)

	return mux
}

// handleIndex renders the plugin list page.
func (h *Handler) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

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
		h.tmpl.ExecuteTemplate(w, "plugin_status_fragment", p)
		return
	}

	data := map[string]any{
		"Plugin": p,
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

// render executes a layout template with a nested page template.
func (h *Handler) render(w http.ResponseWriter, layout, page string, data any) {
	// Clone the template set so we can set the content block
	t, err := h.tmpl.Clone()
	if err != nil {
		h.serverError(w, "cloning templates", err)
		return
	}

	// The page template defines "title" and "content" blocks that the layout uses
	_, err = t.ParseFS(templateFS, "templates/"+page)
	if err != nil {
		h.serverError(w, "parsing page template", err)
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

func (h *Handler) serverError(w http.ResponseWriter, action string, err error) {
	h.logger.Error(action, "error", err)
	http.Error(w, "Internal server error", http.StatusInternalServerError)
}
