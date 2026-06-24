package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
)

// updateInfo describes an available update for one plugin. Either a registry
// version bump ("version") or a newer image digest ("image"), or both.
type updateInfo struct {
	Name             string `json:"name"`
	Image            string `json:"image"`
	Reason           string `json:"reason"` // "version", "image", or "version+image"
	InstalledVersion string `json:"installed_version,omitempty"`
	LatestVersion    string `json:"latest_version,omitempty"`
	LocalDigest      string `json:"local_digest,omitempty"`
	RemoteDigest     string `json:"remote_digest,omitempty"`
	HasUpdate        bool   `json:"has_update"`
}

// updateCacheMu guards reads/writes of the persisted update cache file.
var updateCacheMu sync.Mutex

func updateCachePath(dataDir string) string {
	return filepath.Join(dataDir, "updates.json")
}

// loadUpdateCache reads the persisted update state. Returns an empty slice if
// the cache doesn't exist or can't be parsed.
func loadUpdateCache(dataDir string) []updateInfo {
	updateCacheMu.Lock()
	defer updateCacheMu.Unlock()

	data, err := os.ReadFile(updateCachePath(dataDir))
	if err != nil {
		return nil
	}
	var cached []updateInfo
	if err := json.Unmarshal(data, &cached); err != nil {
		return nil
	}
	return cached
}

// saveUpdateCache persists the current update state so a dashboard reload can
// re-display which plugins are updateable without re-running the full check.
func saveUpdateCache(dataDir string, updates []updateInfo) {
	updateCacheMu.Lock()
	defer updateCacheMu.Unlock()

	if updates == nil {
		updates = []updateInfo{}
	}
	data, err := json.MarshalIndent(updates, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(updateCachePath(dataDir), data, 0644)
}

// updatesByName converts a cached slice into a name→info map for templates.
// The value is a pointer so a missing key yields nil (template-falsy) rather
// than a zero struct (which templates treat as truthy).
func updatesByName(updates []updateInfo) map[string]*updateInfo {
	m := make(map[string]*updateInfo, len(updates))
	for i := range updates {
		u := updates[i]
		m[u.Name] = &u
	}
	return m
}

// handleCheckUpdates checks each installed plugin for both registry version
// bumps and newer image digests, then persists the result.
func (h *Handler) handleCheckUpdates(w http.ResponseWriter, r *http.Request) {
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.serverError(w, "listing plugins", err)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	// merged[name] accumulates version and/or digest signals per plugin.
	merged := make(map[string]*updateInfo)

	// 1. Version-based: compare installed versions against the registry.
	//    Catches local-only images (no GHCR) whose version was bumped.
	installed := make(map[string]string)
	for _, p := range plugins {
		installed[p.Name] = p.Manifest.Version
	}
	mgr := registry.NewManager(h.deps.Config.Plugger.DataDir)
	if versionUpdates, err := mgr.CheckUpdates(installed); err == nil {
		for _, u := range versionUpdates {
			merged[u.Name] = &updateInfo{
				Name:             u.Name,
				Image:            u.Image,
				Reason:           "version",
				InstalledVersion: u.InstalledVersion,
				LatestVersion:    u.LatestVersion,
				HasUpdate:        true,
			}
		}
	}

	// 2. Digest-based: pull each image and compare digests. Local-only images
	//    that can't be pulled are skipped (the version check covers them).
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

		if localDigest == remoteDigest {
			continue
		}

		local := truncDigest(localDigest)
		remote := truncDigest(remoteDigest)

		if existing, ok := merged[p.Name]; ok {
			existing.Reason = "version+image"
			existing.LocalDigest = local
			existing.RemoteDigest = remote
		} else {
			merged[p.Name] = &updateInfo{
				Name:         p.Name,
				Image:        image,
				Reason:       "image",
				LocalDigest:  local,
				RemoteDigest: remote,
				HasUpdate:    true,
			}
		}
	}

	results := make([]updateInfo, 0, len(merged))
	for _, u := range merged {
		results = append(results, *u)
	}

	saveUpdateCache(h.deps.Config.Plugger.DataDir, results)

	h.json(w, http.StatusOK, map[string]any{
		"updates": results,
		"checked": len(plugins),
	})
}

func truncDigest(d string) string {
	if len(d) > 19 {
		return d[:19]
	}
	return d
}

// updatePluginImage pulls the latest image and restarts the plugin if running.
// Used as a fallback for plugins not present in any registry. Returns an error
// describing the first failed step, or nil on success.
func (h *Handler) updatePluginImage(ctx context.Context, p *plugin.Plugin) error {
	image := p.Manifest.Image
	if image == "" {
		return fmt.Errorf("no image configured")
	}
	if err := h.deps.Runtime.Pull(ctx, image); err != nil {
		return fmt.Errorf("pull failed: %w", err)
	}
	if p.State == "running" {
		if err := lifecycle.RestartPlugin(ctx, h.deps, p); err != nil {
			return fmt.Errorf("restart failed: %w", err)
		}
	}
	return nil
}

// reinstallPlugin updates a plugin by reinstalling from the registry: pull the
// new image, refresh the manifest/metadata (preserving env overrides + enabled
// state), then restart. The restart is handed to the owning daemon scheduler
// when there is one, so we don't race its watch loop. Plugins not in any
// registry fall back to a plain image pull + restart.
func (h *Handler) reinstallPlugin(ctx context.Context, p *plugin.Plugin) error {
	wasRunning, _, _, err := lifecycle.PrepareReinstall(ctx, h.deps, p.Name)
	if err != nil {
		// Not in a registry (or pull failed) — fall back to image-only update.
		return h.updatePluginImage(ctx, p)
	}

	if !wasRunning {
		return nil // manifest refreshed; nothing to restart
	}

	// Prefer the scheduler that owns this plugin: it reloads the manifest from
	// the store and restarts with the new image as the single actor.
	if h.restarter != nil && h.restarter.TriggerRestart(p.Name) {
		return nil
	}

	// No scheduler owns it (cron/event/manual) — restart it ourselves using the
	// freshly-stored manifest.
	fresh, err := h.deps.Store.Get(p.Name)
	if err != nil {
		return err
	}
	if err := lifecycle.RestartPlugin(ctx, h.deps, fresh); err != nil {
		return fmt.Errorf("restart failed: %w", err)
	}
	return nil
}

// handleUpdatePlugin pulls the latest image and restarts the plugin.
func (h *Handler) handleUpdatePlugin(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	if err := h.reinstallPlugin(ctx, p); err != nil {
		h.json(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return
	}

	h.markUpdated(p)

	h.json(w, http.StatusOK, map[string]string{
		"status": "updated",
		"name":   name,
		"image":  p.Manifest.Image,
	})
}

// handleUpdateAll updates every plugin currently in the update cache. Each
// plugin is attempted independently; failures are reported per-plugin and
// don't abort the rest. Successful updates are cleared from the cache.
func (h *Handler) handleUpdateAll(w http.ResponseWriter, r *http.Request) {
	cached := loadUpdateCache(h.deps.Config.Plugger.DataDir)
	if len(cached) == 0 {
		h.json(w, http.StatusOK, map[string]any{"updated": []string{}, "failed": map[string]string{}})
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	updated := []string{}
	failed := map[string]string{}

	for _, u := range cached {
		p, err := h.deps.Store.Get(u.Name)
		if err != nil {
			failed[u.Name] = "not found"
			continue
		}
		if err := h.reinstallPlugin(ctx, p); err != nil {
			failed[u.Name] = err.Error()
			continue
		}
		updated = append(updated, u.Name)
		h.markUpdated(p)
	}

	h.json(w, http.StatusOK, map[string]any{
		"updated": updated,
		"failed":  failed,
	})
}

// clearUpdateCacheEntry removes one plugin from the persisted update cache and
// returns the entry that was removed (nil if it wasn't cached).
func clearUpdateCacheEntry(dataDir, name string) *updateInfo {
	cached := loadUpdateCache(dataDir)
	var removed *updateInfo
	filtered := make([]updateInfo, 0, len(cached))
	for i := range cached {
		if cached[i].Name == name {
			u := cached[i]
			removed = &u
			continue
		}
		filtered = append(filtered, cached[i])
	}
	saveUpdateCache(dataDir, filtered)
	return removed
}

// markUpdated clears the cache entry for a freshly-updated plugin so its badge
// disappears. Note: a registry version bump won't change the installed
// manifest version (pull+restart only updates the image) — a full
// reinstall from the registry is required for that. The next update check may
// re-flag version-only differences until the plugin is reinstalled.
func (h *Handler) markUpdated(p *plugin.Plugin) {
	clearUpdateCacheEntry(h.deps.Config.Plugger.DataDir, p.Name)
}
