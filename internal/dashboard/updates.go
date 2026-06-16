package dashboard

import (
	"context"
	"net/http"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
)

// handleCheckUpdates compares local image digests with remote for all installed plugins.
func (h *Handler) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.serverError(w, "listing plugins", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	type updateInfo struct {
		Name        string `json:"name"`
		Image       string `json:"image"`
		LocalDigest string `json:"local_digest"`
		RemoteDigest string `json:"remote_digest"`
		HasUpdate   bool   `json:"has_update"`
	}

	var results []updateInfo

	for _, p := range plugins {
		image := p.Manifest.Image
		if image == "" {
			continue
		}

		localDigest, err := h.deps.Runtime.ImageDigest(ctx, image)
		if err != nil || localDigest == "" {
			continue
		}

		if err := h.deps.Runtime.Pull(ctx, image); err != nil {
			continue
		}

		remoteDigest, err := h.deps.Runtime.ImageDigest(ctx, image)
		if err != nil || remoteDigest == "" {
			continue
		}

		hasUpdate := localDigest != remoteDigest
		local := localDigest
		remote := remoteDigest
		if len(local) > 19 {
			local = local[:19]
		}
		if len(remote) > 19 {
			remote = remote[:19]
		}

		if hasUpdate {
			results = append(results, updateInfo{
				Name:        p.Name,
				Image:       image,
				LocalDigest: local,
				RemoteDigest: remote,
				HasUpdate:   true,
			})
		}
	}

	h.json(w, http.StatusOK, map[string]any{
		"updates": results,
		"checked": len(plugins),
	})
}

// handleUpdatePlugin pulls the latest image and restarts the plugin.
func (h *Handler) handleUpdatePlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	image := p.Manifest.Image
	if image == "" {
		h.json(w, http.StatusBadRequest, map[string]string{"error": "no image configured"})
		return
	}

	if err := h.deps.Runtime.Pull(ctx, image); err != nil {
		h.json(w, http.StatusBadGateway, map[string]string{"error": "pull failed: " + err.Error()})
		return
	}

	if p.State == "running" {
		if err := lifecycle.RestartPlugin(ctx, h.deps, p); err != nil {
			h.json(w, http.StatusInternalServerError, map[string]string{
				"status": "pulled",
				"error":  "restart failed: " + err.Error(),
			})
			return
		}
	}

	h.json(w, http.StatusOK, map[string]string{
		"status": "updated",
		"name":   name,
		"image":  image,
	})
}
