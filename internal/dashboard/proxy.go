package dashboard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

// handlePluginProxy reverse-proxies requests to plugin container UIs.
// Route: /plugins/{name}/ui/...
func (h *Handler) handlePluginProxy(w http.ResponseWriter, r *http.Request) {
	// Extract plugin name from path: /plugins/{name}/ui/...
	name := r.PathValue("name")
	if name == "" {
		// Fallback: parse from URL path
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/plugins/"), "/", 2)
		if len(parts) > 0 {
			name = parts[0]
		}
	}

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if p.ContainerID == "" {
		http.Error(w, "Plugin is not running", http.StatusServiceUnavailable)
		return
	}

	// Get the first UI/API port from metadata, or default to 8080
	containerPort := 8080
	if p.Metadata != nil {
		for _, ps := range p.Metadata.Ports {
			if ps.Type == "ui" || ps.Type == "api" {
				containerPort = ps.Port
				break
			}
		}
	}

	// Discover the actual host port via container inspect
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	info, err := h.deps.Runtime.Inspect(ctx, p.ContainerID)
	if err != nil {
		h.logger.Error("inspecting container for proxy", "plugin", name, "error", err)
		http.Error(w, "Cannot reach plugin container", http.StatusBadGateway)
		return
	}

	hostPort, ok := info.Ports[containerPort]
	if !ok || hostPort == 0 {
		http.Error(w, fmt.Sprintf("Port %d not exposed on host", containerPort), http.StatusBadGateway)
		return
	}

	// Strip the /plugins/{name}/ui prefix from the path
	prefix := fmt.Sprintf("/plugins/%s/ui", name)
	targetPath := strings.TrimPrefix(r.URL.Path, prefix)
	if targetPath == "" {
		targetPath = "/"
	}

	target, _ := url.Parse(fmt.Sprintf("http://localhost:%d", hostPort))
	proxy := &httputil.ReverseProxy{
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = targetPath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Error("proxy error", "plugin", name, "error", err)
			http.Error(w, "Plugin unreachable", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}
