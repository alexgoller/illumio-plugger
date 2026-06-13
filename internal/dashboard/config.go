package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

// pluginConfig holds config fields for a single plugin in the unified view.
type pluginConfig struct {
	Plugin *plugin.Plugin
	Fields []configField
}

// configField is a unified view of a config item for template rendering.
type configField struct {
	Name        string
	Description string
	Type        string // string, int, bool, secret
	Required    bool
	Default     string
	Example     string
	Validation  string
	Value       string // current effective value
	Source      string // "manifest", "metadata", or "override"
	Secret      bool
}

// BuildConfigFields merges manifest env vars and metadata config into
// a unified list for the config form.
func BuildConfigFields(p *plugin.Plugin) []configField {
	seen := make(map[string]bool)
	var fields []configField

	// Metadata config specs first (richer info)
	if p.Metadata != nil {
		for _, c := range p.Metadata.Config {
			val := c.Default
			source := "default"
			if override, ok := p.EnvOverrides[c.Name]; ok {
				val = override
				source = "override"
			}
			fields = append(fields, configField{
				Name:        c.Name,
				Description: c.Description,
				Type:        c.Type,
				Required:    c.Required,
				Default:     c.Default,
				Example:     c.Example,
				Validation:  c.Validation,
				Value:       val,
				Source:      source,
				Secret:      c.Type == "secret",
			})
			seen[c.Name] = true
		}
	}

	// Manifest env vars (skip duplicates from metadata)
	for _, e := range p.Manifest.Env {
		if seen[e.Name] {
			continue
		}
		val := e.Default
		source := "default"
		if override, ok := p.EnvOverrides[e.Name]; ok {
			val = override
			source = "override"
		}
		typ := "string"
		if e.Secret {
			typ = "secret"
		}
		fields = append(fields, configField{
			Name:     e.Name,
			Type:     typ,
			Required: e.Required,
			Default:  e.Default,
			Value:    val,
			Source:   source,
			Secret:   e.Secret,
		})
	}

	return fields
}

func (h *Handler) handleSaveConfig(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.renderConfigSection(w, p, "Invalid form data")
		return
	}

	// Collect all env_ prefixed fields
	newOverrides := make(map[string]string)
	for key, values := range r.Form {
		if strings.HasPrefix(key, "env_") && len(values) > 0 {
			envName := strings.TrimPrefix(key, "env_")
			val := strings.TrimSpace(values[0])
			if val != "" {
				newOverrides[envName] = val
			}
		}
	}

	// Handle bool checkboxes (unchecked = not in form, set to "false")
	allFields := BuildConfigFields(p)
	for _, f := range allFields {
		if f.Type == "bool" {
			if _, inForm := newOverrides[f.Name]; !inForm {
				newOverrides[f.Name] = "false"
			}
		}
	}

	// Validate required fields
	var validationErrors []string
	for _, f := range allFields {
		if f.Required {
			val := newOverrides[f.Name]
			if val == "" && f.Default == "" {
				validationErrors = append(validationErrors, fmt.Sprintf("%s is required", f.Name))
			}
		}
		// Regex validation
		if f.Validation != "" {
			val := newOverrides[f.Name]
			if val != "" {
				re, err := regexp.Compile(f.Validation)
				if err == nil && !re.MatchString(val) {
					validationErrors = append(validationErrors, fmt.Sprintf("%s: invalid format", f.Name))
				}
			}
		}
	}

	if len(validationErrors) > 0 {
		h.renderConfigSection(w, p, strings.Join(validationErrors, "; "))
		return
	}

	// Update overrides
	p.EnvOverrides = newOverrides
	if err := h.deps.Store.Put(p); err != nil {
		h.renderConfigSection(w, p, "Failed to save: "+err.Error())
		return
	}

	// Auto-restart if requested
	restart := r.FormValue("restart") == "true"
	msg := "Configuration saved."
	if restart && p.State == plugin.StateRunning {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		if err := lifecycle.RestartPlugin(ctx, h.deps, p); err != nil {
			msg = "Saved but restart failed: " + err.Error()
		} else {
			msg = "Configuration saved and plugin restarted."
			p, _ = h.deps.Store.Get(name) // reload after restart
		}
	} else if p.State == plugin.StateRunning {
		msg = "Configuration saved. Restart to apply changes."
	}

	h.renderConfigSection(w, p, msg)
}

func (h *Handler) renderConfigSection(w http.ResponseWriter, p *plugin.Plugin, message string) {
	fields := BuildConfigFields(p)

	data := map[string]any{
		"Plugin":  p,
		"Fields":  fields,
		"Message": message,
	}

	t, err := template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/plugin_config.html")
	if err != nil {
		h.serverError(w, "parsing config template", err)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	t.ExecuteTemplate(w, "plugin_config", data)
}

func (h *Handler) handleConfigAll(w http.ResponseWriter, r *http.Request) {
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.serverError(w, "listing plugins", err)
		return
	}

	var configs []pluginConfig
	for _, p := range plugins {
		fields := BuildConfigFields(p)
		if len(fields) > 0 {
			configs = append(configs, pluginConfig{Plugin: p, Fields: fields})
		}
	}

	data := map[string]any{
		"PluginConfigs": configs,
		"Message":       "",
	}
	h.render(w, "layout.html", "config_all.html", data)
}

func (h *Handler) handleSaveConfigAll(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.handleConfigAllWithMessage(w, "Invalid form data")
		return
	}

	action := r.FormValue("action")

	// Group form values by plugin: "pluginName::ENV_NAME" -> value
	pluginOverrides := make(map[string]map[string]string)
	for key, values := range r.Form {
		if key == "action" || len(values) == 0 {
			continue
		}
		parts := strings.SplitN(key, "::", 2)
		if len(parts) != 2 {
			continue
		}
		pluginName, envName := parts[0], parts[1]
		if pluginOverrides[pluginName] == nil {
			pluginOverrides[pluginName] = make(map[string]string)
		}
		val := strings.TrimSpace(values[0])
		if val != "" {
			pluginOverrides[pluginName][envName] = val
		}
	}

	// Handle bool checkboxes (unchecked = missing from form)
	plugins, err := h.deps.Store.List()
	if err != nil {
		h.handleConfigAllWithMessage(w, "Failed to list plugins: "+err.Error())
		return
	}

	for _, p := range plugins {
		fields := BuildConfigFields(p)
		for _, f := range fields {
			if f.Type == "bool" {
				if pluginOverrides[p.Name] == nil {
					pluginOverrides[p.Name] = make(map[string]string)
				}
				if _, inForm := pluginOverrides[p.Name][f.Name]; !inForm {
					pluginOverrides[p.Name][f.Name] = "false"
				}
			}
		}
	}

	// Save each plugin's overrides and track which changed
	var changed []string
	var errors []string

	for _, p := range plugins {
		newOverrides, hasOverrides := pluginOverrides[p.Name]
		if !hasOverrides {
			continue
		}

		// Check if anything actually changed
		old := p.EnvOverrides
		if old == nil {
			old = make(map[string]string)
		}
		modified := false
		for k, v := range newOverrides {
			if old[k] != v {
				modified = true
				break
			}
		}
		if len(old) != len(newOverrides) {
			modified = true
		}

		if !modified {
			continue
		}

		p.EnvOverrides = newOverrides
		if err := h.deps.Store.Put(p); err != nil {
			errors = append(errors, fmt.Sprintf("%s: %s", p.Name, err.Error()))
			continue
		}
		changed = append(changed, p.Name)
	}

	// Restart changed plugins if requested
	if action == "save-restart" && len(changed) > 0 {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
		defer cancel()
		restarted := 0
		for _, name := range changed {
			p, err := h.deps.Store.Get(name)
			if err != nil || p.State != plugin.StateRunning {
				continue
			}
			if err := lifecycle.RestartPlugin(ctx, h.deps, p); err != nil {
				slog.Warn("config: failed to restart plugin", "plugin", name, "error", err)
				errors = append(errors, fmt.Sprintf("restart %s: %s", name, err.Error()))
			} else {
				restarted++
			}
		}
		if len(errors) > 0 {
			h.handleConfigAllWithMessage(w, fmt.Sprintf("Saved %d plugin(s), restarted %d. Errors: %s", len(changed), restarted, strings.Join(errors, "; ")))
		} else {
			h.handleConfigAllWithMessage(w, fmt.Sprintf("Saved and restarted %d plugin(s): %s", restarted, strings.Join(changed, ", ")))
		}
		return
	}

	if len(errors) > 0 {
		h.handleConfigAllWithMessage(w, "Errors: "+strings.Join(errors, "; "))
		return
	}
	if len(changed) == 0 {
		h.handleConfigAllWithMessage(w, "No changes detected.")
		return
	}
	h.handleConfigAllWithMessage(w, fmt.Sprintf("Saved %d plugin(s): %s. Restart to apply.", len(changed), strings.Join(changed, ", ")))
}

func (h *Handler) handleConfigAllWithMessage(w http.ResponseWriter, message string) {
	plugins, _ := h.deps.Store.List()
	var configs []pluginConfig
	for _, p := range plugins {
		fields := BuildConfigFields(p)
		if len(fields) > 0 {
			configs = append(configs, pluginConfig{Plugin: p, Fields: fields})
		}
	}
	data := map[string]any{
		"PluginConfigs": configs,
		"Message":       message,
	}
	h.render(w, "layout.html", "config_all.html", data)
}
