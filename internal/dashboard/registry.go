package dashboard

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
)

// handleRegistryPage renders the plugin registry browser.
func (h *Handler) handleRegistryPage(w http.ResponseWriter, r *http.Request) {
	h.render(w, "layout.html", "registry.html", nil)
}

// handleAPIRegistry returns registry data as JSON.
func (h *Handler) handleAPIRegistry(w http.ResponseWriter, r *http.Request) {
	mgr := registry.NewManager(h.deps.Config.Plugger.DataDir)

	registries, _ := mgr.FetchAll()
	var allPlugins []registry.Plugin
	for _, reg := range registries {
		allPlugins = append(allPlugins, reg.Plugins...)
	}

	installed, _ := h.deps.Store.List()
	installedMap := make(map[string]string)
	for _, p := range installed {
		installedMap[p.Name] = p.Manifest.Version
	}

	updates, _ := mgr.CheckUpdates(installedMap)
	updateMap := make(map[string]string)
	for _, u := range updates {
		updateMap[u.Name] = u.LatestVersion
	}

	repos, _ := mgr.ListRepos()

	h.json(w, http.StatusOK, map[string]any{
		"plugins":   allPlugins,
		"installed": installedMap,
		"updates":   updateMap,
		"repos":     repos,
	})
}

// handleAPIRegistryInstall installs a plugin from the registry by name.
func (h *Handler) handleAPIRegistryInstall(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		http.Error(w, "name is required", http.StatusBadRequest)
		return
	}

	if _, err := h.deps.Store.Get(req.Name); err == nil {
		h.json(w, http.StatusConflict, map[string]string{"error": fmt.Sprintf("plugin %q already installed", req.Name)})
		return
	}

	mgr := registry.NewManager(h.deps.Config.Plugger.DataDir)
	regPlugin, err := mgr.FindPlugin(req.Name)
	if err != nil {
		h.json(w, http.StatusNotFound, map[string]string{"error": err.Error()})
		return
	}

	slog.Info("installing from registry", "plugin", req.Name, "image", regPlugin.Image)

	ctx := r.Context()
	if err := h.deps.Runtime.Pull(ctx, regPlugin.Image); err != nil {
		h.json(w, http.StatusBadGateway, map[string]string{"error": fmt.Sprintf("pull failed: %v", err)})
		return
	}

	// Extract manifest
	var m *config.PluginManifest
	manifestBytes, mErr := h.deps.Runtime.CopyFromImage(ctx, regPlugin.Image, "/.plugger/manifest.yaml")
	if mErr != nil {
		manifestBytes, mErr = h.deps.Runtime.CopyFromImage(ctx, regPlugin.Image, "/.plugger/plugin.yaml")
	}
	if mErr == nil {
		m, _ = config.LoadManifestFromBytes(manifestBytes)
	}
	if m == nil {
		mode := regPlugin.Mode
		if mode == "" {
			mode = "daemon"
		}
		m = &config.PluginManifest{
			Name:    regPlugin.Name,
			Version: regPlugin.Version,
			Image:   regPlugin.Image,
			Schedule: config.ScheduleConfig{Mode: mode},
		}
	}
	m.Image = regPlugin.Image

	// Discover metadata
	var metadata *config.ContainerMetadata
	metadataBytes, mdErr := h.deps.Runtime.CopyFromImage(ctx, regPlugin.Image, "/.plugger/metadata.yaml")
	if mdErr == nil {
		metadata, _ = config.ParseMetadata(metadataBytes)
	}

	now := time.Now()
	p := &plugin.Plugin{
		Name:        m.Name,
		Manifest:    *m,
		Metadata:    metadata,
		State:       plugin.StateInstalled,
		Enabled:     true,
		InstalledAt: now,
	}

	if err := h.deps.Store.Put(p); err != nil {
		h.json(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	slog.Info("installed from registry", "plugin", req.Name, "version", regPlugin.Version)
	h.json(w, http.StatusOK, map[string]string{"success": "true", "name": req.Name, "version": regPlugin.Version})
}
