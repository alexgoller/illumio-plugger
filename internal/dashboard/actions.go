package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

func (h *Handler) handleStartPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if p.State == plugin.StateRunning {
		h.renderRow(w, p)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	// Remove old container if exists
	if p.ContainerID != "" {
		_ = h.deps.Runtime.Remove(ctx, p.ContainerID)
	}

	if err := lifecycle.StartPlugin(ctx, h.deps, p); err != nil {
		h.logger.Error("starting plugin", "name", name, "error", err)
		p.State = plugin.StateErrored
		p.LastError = err.Error()
		h.deps.Store.Put(p)
	}

	// Re-read from store to get updated state
	p, _ = h.deps.Store.Get(name)
	h.renderRow(w, p)
}

func (h *Handler) handleStopPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	if err := lifecycle.StopPlugin(ctx, h.deps, p); err != nil {
		h.logger.Error("stopping plugin", "name", name, "error", err)
	}

	p, _ = h.deps.Store.Get(name)
	h.renderRow(w, p)
}

func (h *Handler) handleRestartPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	if err := lifecycle.RestartPlugin(ctx, h.deps, p); err != nil {
		h.logger.Error("restarting plugin", "name", name, "error", err)
		p.State = plugin.StateErrored
		p.LastError = err.Error()
		h.deps.Store.Put(p)
	}

	p, _ = h.deps.Store.Get(name)
	h.renderRow(w, p)
}

func (h *Handler) handleUninstallPlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	// Stop and remove container
	_ = h.deps.Runtime.Stop(ctx, p.ContainerName(), 10*time.Second)
	_ = h.deps.Runtime.Remove(ctx, p.ContainerName())
	if p.ContainerID != "" {
		_ = h.deps.Runtime.Stop(ctx, p.ContainerID, 10*time.Second)
		_ = h.deps.Runtime.Remove(ctx, p.ContainerID)
	}

	// Remove from store
	if err := h.deps.Store.Delete(name); err != nil {
		h.logger.Error("uninstalling plugin", "name", name, "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	h.logger.Info("plugin uninstalled via dashboard", "name", name)

	// Return empty row (htmx will remove the element) or redirect
	w.Header().Set("HX-Redirect", "/")
	w.WriteHeader(http.StatusOK)
}

func (h *Handler) renderRow(w http.ResponseWriter, p *plugin.Plugin) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := h.tmpl.ExecuteTemplate(w, "plugin_row", p); err != nil {
		h.logger.Error("rendering plugin row", "error", err)
	}
}
