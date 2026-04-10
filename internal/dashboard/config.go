package dashboard

import (
	"context"
	"fmt"
	"html/template"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/lifecycle"
	"github.com/illumio/plugger/internal/plugin"
)

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
