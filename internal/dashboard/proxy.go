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

// attrPattern matches href="...", src="...", action="..." with absolute paths.
var attrPattern = regexp.MustCompile(`((?:href|src|action)=["'])(/[^"']*)(["'])`)

// pluggerProxyScript is injected into every HTML page served through the proxy.
// It monkey-patches fetch, XMLHttpRequest, WebSocket, and window.location
// assignments so that absolute paths (e.g. /api/events) are automatically
// prefixed with the proxy base path. This is more robust than regex-based
// rewriting of JS source code.
const pluggerProxyScript = `<script data-plugger-proxy>
(function() {
    var B = '%s';
    if (!B) return;
    window.__PLUGGER_BASE = B;

    function rewrite(u) {
        if (typeof u !== 'string') return u;
        if (u.startsWith(B)) return u;
        if (u.startsWith('/') && !u.startsWith('//')) return B.replace(/\/$/, '') + u;
        return u;
    }

    // Patch fetch
    var _fetch = window.fetch;
    window.fetch = function(input, init) {
        if (typeof input === 'string') input = rewrite(input);
        else if (input instanceof Request) input = new Request(rewrite(input.url), input);
        return _fetch.call(this, input, init);
    };

    // Patch XMLHttpRequest
    var _xhrOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        arguments[1] = rewrite(url);
        return _xhrOpen.apply(this, arguments);
    };

    // Patch EventSource (SSE)
    if (window.EventSource) {
        var _ES = window.EventSource;
        window.EventSource = function(url, opts) {
            return new _ES(rewrite(url), opts);
        };
        window.EventSource.prototype = _ES.prototype;
        Object.defineProperty(window.EventSource, 'CONNECTING', {value: 0});
        Object.defineProperty(window.EventSource, 'OPEN', {value: 1});
        Object.defineProperty(window.EventSource, 'CLOSED', {value: 2});
    }

    // Patch WebSocket
    if (window.WebSocket) {
        var _WS = window.WebSocket;
        window.WebSocket = function(url, protocols) {
            return new _WS(rewrite(url), protocols);
        };
        window.WebSocket.prototype = _WS.prototype;
    }

    // Patch window.location assignments via history
    var _pushState = history.pushState;
    history.pushState = function(state, title, url) {
        return _pushState.call(this, state, title, rewrite(url));
    };
    var _replaceState = history.replaceState;
    history.replaceState = function(state, title, url) {
        return _replaceState.call(this, state, title, rewrite(url));
    };

    // Patch form submissions
    document.addEventListener('submit', function(e) {
        var form = e.target;
        if (form && form.action) {
            try {
                var u = new URL(form.action);
                if (u.origin === window.location.origin && !u.pathname.startsWith(B)) {
                    form.action = rewrite(u.pathname + u.search);
                }
            } catch(x) {}
        }
    }, true);
})();
</script>`

// handlePluginProxy reverse-proxies requests to plugin container UIs.
// Injects a monkey-patch script into HTML responses so that all JS API
// calls are automatically routed through the proxy prefix.
func (h *Handler) handlePluginProxy(w http.ResponseWriter, r *http.Request) {
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

	containerPort := 8080
	if p.Metadata != nil {
		for _, ps := range p.Metadata.Ports {
			if ps.Type == "ui" || ps.Type == "api" {
				containerPort = ps.Port
				break
			}
		}
	}

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

	prefix := fmt.Sprintf("/plugins/%s/ui", name)
	baseHref := prefix + "/"
	targetPath := strings.TrimPrefix(r.URL.Path, prefix)
	if targetPath == "" {
		targetPath = "/"
	}

	target, _ := url.Parse(fmt.Sprintf("http://localhost:%d", hostPort))
	proxy := &httputil.ReverseProxy{
		// Flush immediately for streaming responses (SSE, chunked)
		FlushInterval: -1,
		Director: func(req *http.Request) {
			req.URL.Scheme = target.Scheme
			req.URL.Host = target.Host
			req.URL.Path = targetPath
			req.URL.RawQuery = r.URL.RawQuery
			req.Host = target.Host
			// Only strip Accept-Encoding for HTML pages (need to rewrite body).
			// Leave it for SSE/API/binary responses so streaming works.
			if r.Header.Get("Accept") == "" || strings.Contains(r.Header.Get("Accept"), "text/html") {
				req.Header.Del("Accept-Encoding")
			}
		},
		ModifyResponse: func(resp *http.Response) error {
			// Rewrite Location headers for redirects
			if loc := resp.Header.Get("Location"); loc != "" {
				if strings.HasPrefix(loc, "/") && !strings.HasPrefix(loc, prefix) {
					resp.Header.Set("Location", strings.TrimSuffix(prefix, "/")+loc)
				}
			}

			ct := resp.Header.Get("Content-Type")

			// Don't buffer streaming responses (SSE, chunked)
			if strings.Contains(ct, "text/event-stream") {
				resp.Header.Set("X-Accel-Buffering", "no")
				resp.Header.Set("Cache-Control", "no-cache")
				return nil
			}

			if !strings.Contains(ct, "text/html") {
				return nil
			}
			return rewriteHTMLBody(resp, baseHref)
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			h.logger.Error("proxy error", "plugin", name, "error", err)
			http.Error(w, "Plugin unreachable", http.StatusBadGateway)
		},
	}

	proxy.ServeHTTP(w, r)
}

// rewriteHTMLBody reads the response, rewrites HTML attributes with absolute
// paths, and injects the proxy monkey-patch script after <head>.
func rewriteHTMLBody(resp *http.Response, baseHref string) error {
	var body []byte
	var err error

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

	// Rewrite HTML attributes (href, src, action)
	body = rewriteHTMLAttributes(body, baseHref)

	// Inject the monkey-patch script after <head>
	script := fmt.Sprintf(pluggerProxyScript, baseHref)
	headIdx := bytes.Index(bytes.ToLower(body), []byte("<head"))
	if headIdx >= 0 {
		closeIdx := bytes.IndexByte(body[headIdx:], '>')
		if closeIdx >= 0 {
			insertAt := headIdx + closeIdx + 1
			newBody := make([]byte, 0, len(body)+len(script))
			newBody = append(newBody, body[:insertAt]...)
			newBody = append(newBody, []byte(script)...)
			newBody = append(newBody, body[insertAt:]...)
			body = newBody
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	return nil
}

// rewriteHTMLAttributes rewrites absolute paths in href, src, action attributes.
func rewriteHTMLAttributes(body []byte, prefix string) []byte {
	return attrPattern.ReplaceAllFunc(body, func(match []byte) []byte {
		parts := attrPattern.FindSubmatch(match)
		if len(parts) != 4 {
			return match
		}
		before := parts[1]
		path := parts[2]
		after := parts[3]

		pathStr := string(path)
		if strings.HasPrefix(pathStr, prefix) {
			return match
		}

		newPath := strings.TrimSuffix(prefix, "/") + pathStr
		result := make([]byte, 0, len(before)+len(newPath)+len(after))
		result = append(result, before...)
		result = append(result, []byte(newPath)...)
		result = append(result, after...)
		return result
	})
}
