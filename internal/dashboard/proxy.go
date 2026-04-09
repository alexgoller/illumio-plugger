package dashboard

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// attrPattern matches href="..." and src="..." with absolute paths.
var attrPattern = regexp.MustCompile(`((?:href|src|action)=["'])(/[^"']*)(["'])`)

// rewriteAbsoluteURLs rewrites absolute paths in HTML attributes to include
// the proxy prefix, so href="/watchers" becomes href="/plugins/name/ui/watchers".
// Skips external URLs (http://, https://, //) and already-prefixed paths.
func rewriteAbsoluteURLs(body []byte, prefix string) []byte {
	return attrPattern.ReplaceAllFunc(body, func(match []byte) []byte {
		parts := attrPattern.FindSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		attr := parts[1]   // e.g. href="
		path := parts[2]   // e.g. /watchers
		quote := parts[3]  // e.g. "

		pathStr := string(path)

		// Skip if already rewritten
		if strings.HasPrefix(pathStr, prefix) {
			return match
		}

		// Rewrite: /watchers -> /plugins/name/ui/watchers
		newPath := strings.TrimSuffix(prefix, "/") + pathStr
		result := make([]byte, 0, len(attr)+len(newPath)+len(quote))
		result = append(result, attr...)
		result = append(result, []byte(newPath)...)
		result = append(result, quote...)
		return result
	})
}

// handlePluginProxy reverse-proxies requests to plugin container UIs.
// Injects a <base> tag into HTML responses so that absolute links
// (e.g. /watchers) resolve correctly through the proxy prefix.
func (h *Handler) handlePluginProxy(w http.ResponseWriter, r *http.Request) {
	// Extract plugin name from path: /plugins/{name}/ui/...
	name := r.PathValue("name")
	if name == "" {
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
	baseHref := prefix + "/"
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
			// Prevent backend from sending compressed responses so we can rewrite
			req.Header.Del("Accept-Encoding")
		},
		ModifyResponse: func(resp *http.Response) error {
			ct := resp.Header.Get("Content-Type")
			if !strings.Contains(ct, "text/html") {
				return nil
			}
			return injectBaseTag(resp, baseHref)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Error("proxy error", "plugin", name, "error", err)
			http.Error(w, "Plugin unreachable", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

// injectBaseTag reads the HTML response body and injects a <base href="...">
// tag after <head> so the browser resolves all relative and absolute URLs
// against the proxy prefix.
func injectBaseTag(resp *http.Response, baseHref string) error {
	var body []byte
	var err error

	// Handle gzip-encoded responses
	if resp.Header.Get("Content-Encoding") == "gzip" {
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return err
		}
		body, err = io.ReadAll(reader)
		reader.Close()
		if err != nil {
			return err
		}
		resp.Header.Del("Content-Encoding")
	} else {
		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
	}
	resp.Body.Close()

	// Rewrite absolute URLs in href and src attributes to go through the proxy.
	// e.g. href="/watchers" -> href="/plugins/pce-events/ui/watchers"
	// Only rewrite paths that don't already start with the prefix.
	body = rewriteAbsoluteURLs(body, baseHref)

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}
