package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
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

	// Clear this plugin from the cached update state — it's now current.
	clearUpdateCacheEntry(h.deps.Config.Plugger.DataDir, name)

	h.json(w, http.StatusOK, map[string]string{
		"status": "updated",
		"name":   name,
		"image":  image,
	})
}

// clearUpdateCacheEntry removes one plugin from the persisted update cache.
func clearUpdateCacheEntry(dataDir, name string) {
	cached := loadUpdateCache(dataDir)
	filtered := make([]updateInfo, 0, len(cached))
	for _, u := range cached {
		if u.Name != name {
			filtered = append(filtered, u)
		}
	}
	saveUpdateCache(dataDir, filtered)
}
