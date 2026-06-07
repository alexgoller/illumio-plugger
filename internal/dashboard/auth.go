package dashboard

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/config"
)

// AuthMiddleware wraps an http.Handler with API key authentication.
// It checks for:
//  1. Bearer token in Authorization header (API key starting with "pk_")
//  2. Session cookie ("plugger_session") for dashboard browser access
//  3. Token in query param (?token=pk_...)
//
// Endpoints that are always open: /healthz, GET /login, POST /login, static assets.
//
// For each request, it determines:
//   - Which API key is being used
//   - Which plugin is being accessed (from URL path)
//   - Whether the access level (read/write) permits the HTTP method
type AuthMiddleware struct {
	config *config.AuthConfig
	keyMap map[string]*config.APIKeyConfig // key value -> config for fast lookup
	secret []byte                          // HMAC secret derived from master key or first key
}

const (
	sessionCookieName = "plugger_session"
	sessionSeparator  = "|"
)

// NewAuthMiddleware builds the auth middleware with a pre-computed key map.
func NewAuthMiddleware(cfg *config.AuthConfig) *AuthMiddleware {
	m := &AuthMiddleware{
		config: cfg,
		keyMap: make(map[string]*config.APIKeyConfig, len(cfg.Keys)),
	}

	for i := range cfg.Keys {
		k := &cfg.Keys[i]
		m.keyMap[k.Key] = k
	}

	// Derive HMAC secret from master key if available, otherwise from first API key
	seed := cfg.MasterKey
	if seed == "" && len(cfg.Keys) > 0 {
		seed = cfg.Keys[0].Key
	}
	if seed == "" {
		seed = "plugger-default-session-secret"
	}
	h := sha256.Sum256([]byte("plugger-session-secret:" + seed))
	m.secret = h[:]

	return m
}

// Wrap returns an http.Handler that enforces authentication before delegating
// to the wrapped handler.
func (a *AuthMiddleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always allow: health check, login page, static CDN assets
		if a.isOpenPath(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Try to extract a token from the request
		token := a.extractToken(r)

		// Try session cookie if no bearer/query token
		var key *config.APIKeyConfig
		if token != "" {
			key = a.ValidateKey(token)
		} else {
			key = a.ValidateSession(r)
		}

		if key == nil {
			// No valid auth — decide response based on request type
			if a.isAPIRequest(r) {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			} else {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			}
			return
		}

		// Extract plugin name from path if this is a plugin-specific route
		pluginName := a.extractPluginName(r.URL.Path)

		// For plugin-specific routes, check access
		if pluginName != "" {
			if !a.CheckAccess(key, pluginName, r.Method) {
				if a.isAPIRequest(r) {
					http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				} else {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}
				return
			}
		} else {
			// Dashboard-level route (not plugin-specific) — require dashboard access
			if !a.hasDashboardAccess(key) {
				if a.isAPIRequest(r) {
					http.Error(w, `{"error":"forbidden — no dashboard access"}`, http.StatusForbidden)
				} else {
					http.Error(w, "Forbidden", http.StatusForbidden)
				}
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// ValidateKey checks a token against the master key and all configured API keys.
// Uses constant-time comparison to prevent timing attacks.
func (a *AuthMiddleware) ValidateKey(token string) *config.APIKeyConfig {
	// Check master key first
	if a.config.MasterKey != "" {
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.config.MasterKey)) == 1 {
			// Master key gets full access — synthesize a virtual key config
			return &config.APIKeyConfig{
				Key:       a.config.MasterKey,
				Name:      "master",
				Access:    "write",
				Dashboard: true,
				Plugins:   map[string]string{"*": "write"},
			}
		}
	}

	// Check all configured keys (constant-time compare against each)
	var matched *config.APIKeyConfig
	for _, k := range a.config.Keys {
		if subtle.ConstantTimeCompare([]byte(token), []byte(k.Key)) == 1 {
			matched = a.keyMap[k.Key]
		}
	}
	return matched
}

// CheckAccess determines whether a key has permission for the given plugin and HTTP method.
// "read" access allows GET and HEAD. "write" access allows all methods.
func (a *AuthMiddleware) CheckAccess(key *config.APIKeyConfig, pluginName string, method string) bool {
	// Determine the access level for this plugin
	level := ""

	// Check explicit plugin mapping first
	if key.Plugins != nil {
		if pl, ok := key.Plugins[pluginName]; ok {
			level = pl
		} else if wl, ok := key.Plugins["*"]; ok {
			// Wildcard entry
			level = wl
		}
	}

	// Fall back to key-level default access
	if level == "" {
		level = key.Access
	}

	// No access configured at all — deny
	if level == "" {
		return false
	}

	return a.methodAllowed(level, method)
}

// CreateSession creates a signed session cookie value for the given key.
// The cookie value format is: hex(hmac)|timestamp|keyName
func (a *AuthMiddleware) CreateSession(key *config.APIKeyConfig) (string, time.Time) {
	ttl := a.config.Dashboard.SessionTTL
	if ttl <= 0 {
		ttl = 86400 // 24h default
	}
	expiry := time.Now().Add(time.Duration(ttl) * time.Second)
	expiryStr := fmt.Sprintf("%d", expiry.Unix())

	payload := key.Key + sessionSeparator + expiryStr
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))

	cookieVal := sig + sessionSeparator + expiryStr + sessionSeparator + key.Key
	return cookieVal, expiry
}

// ValidateSession reads and validates the session cookie from the request.
// Returns the matching APIKeyConfig or nil if the session is invalid/expired.
func (a *AuthMiddleware) ValidateSession(r *http.Request) *config.APIKeyConfig {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil || cookie.Value == "" {
		return nil
	}

	parts := strings.SplitN(cookie.Value, sessionSeparator, 3)
	if len(parts) != 3 {
		return nil
	}

	sig := parts[0]
	expiryStr := parts[1]
	keyVal := parts[2]

	// Check expiry
	var expiry int64
	if _, err := fmt.Sscanf(expiryStr, "%d", &expiry); err != nil {
		return nil
	}
	if time.Now().Unix() > expiry {
		return nil
	}

	// Verify HMAC signature
	payload := keyVal + sessionSeparator + expiryStr
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(payload))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(sig), []byte(expectedSig)) != 1 {
		return nil
	}

	// Look up the key
	return a.ValidateKey(keyVal)
}

// HandleLogin serves the login page (GET) and processes login submissions (POST).
func (a *AuthMiddleware) HandleLogin(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		a.serveLoginPage(w, "")
	case http.MethodPost:
		a.processLogin(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// HandleLogout clears the session cookie and redirects to login.
func (a *AuthMiddleware) HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	if a.isAPIRequest(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"logged out"}`)
	} else {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

// processLogin validates the submitted key and sets the session cookie.
func (a *AuthMiddleware) processLogin(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		a.serveLoginPage(w, "Invalid form submission")
		return
	}

	token := strings.TrimSpace(r.FormValue("key"))
	if token == "" {
		a.serveLoginPage(w, "Please enter an API key")
		return
	}

	key := a.ValidateKey(token)
	if key == nil {
		a.serveLoginPage(w, "Invalid API key")
		return
	}

	if !a.hasDashboardAccess(key) {
		a.serveLoginPage(w, "This key does not have dashboard access")
		return
	}

	cookieVal, expiry := a.CreateSession(key)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    cookieVal,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	// Redirect to the original destination or home
	redirect := r.FormValue("redirect")
	if redirect == "" || redirect == "/login" {
		redirect = "/"
	}
	http.Redirect(w, r, redirect, http.StatusSeeOther)
}

// isOpenPath returns true for paths that should never require authentication.
func (a *AuthMiddleware) isOpenPath(r *http.Request) bool {
	path := r.URL.Path

	// Health check
	if path == "/healthz" {
		return true
	}

	// Login page
	if path == "/login" {
		return true
	}

	// CDN-loaded assets (tailwind, htmx) are external, not served by us

	return false
}

// extractToken extracts an API token from the request.
// Checks Authorization header first, then query parameter.
func (a *AuthMiddleware) extractToken(r *http.Request) string {
	// Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	// Query parameter: ?token=pk_...
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		return qToken
	}

	return ""
}

// extractPluginName extracts a plugin name from the URL path if this is a
// plugin-specific route.
func (a *AuthMiddleware) extractPluginName(path string) string {
	// /plugins/{name}/ui/...
	if strings.HasPrefix(path, "/plugins/") {
		rest := strings.TrimPrefix(path, "/plugins/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	// /api/plugins/{name}/...
	if strings.HasPrefix(path, "/api/plugins/") {
		rest := strings.TrimPrefix(path, "/api/plugins/")
		parts := strings.SplitN(rest, "/", 2)
		if len(parts) > 0 && parts[0] != "" {
			return parts[0]
		}
	}

	return ""
}

// isAPIRequest returns true if the request is an API call (expects JSON).
func (a *AuthMiddleware) isAPIRequest(r *http.Request) bool {
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		return true
	}
	return false
}

// hasDashboardAccess checks whether a key has dashboard-level access.
func (a *AuthMiddleware) hasDashboardAccess(key *config.APIKeyConfig) bool {
	return key.Dashboard
}

// methodAllowed checks if an HTTP method is permitted at the given access level.
func (a *AuthMiddleware) methodAllowed(level, method string) bool {
	switch level {
	case "write":
		return true
	case "read":
		return method == http.MethodGet || method == http.MethodHead || method == http.MethodOptions
	default:
		return false
	}
}

// serveLoginPage renders the login HTML page with an optional error message.
func (a *AuthMiddleware) serveLoginPage(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	errorHTML := ""
	if errMsg != "" {
		errorHTML = `<div style="background:#dc2626;color:#fff;padding:10px 16px;border-radius:8px;margin-bottom:20px;font-size:14px;">` + errMsg + `</div>`
	}

	fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Plugger</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #11111b;
            color: #cdd6f4;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .login-card {
            background: #1e1e2e;
            border: 1px solid #313244;
            border-radius: 16px;
            padding: 40px;
            width: 100%%;
            max-width: 400px;
            box-shadow: 0 25px 50px rgba(0,0,0,0.4);
        }
        .logo {
            text-align: center;
            margin-bottom: 32px;
        }
        .logo svg {
            width: 48px;
            height: 48px;
            color: #89b4fa;
        }
        .logo h1 {
            font-size: 24px;
            font-weight: 700;
            color: #cdd6f4;
            margin-top: 12px;
        }
        .logo p {
            font-size: 14px;
            color: #6c7086;
            margin-top: 4px;
        }
        label {
            display: block;
            font-size: 14px;
            color: #a6adc8;
            margin-bottom: 8px;
            font-weight: 500;
        }
        input[type="password"] {
            width: 100%%;
            padding: 12px 16px;
            background: #313244;
            border: 1px solid #45475a;
            border-radius: 8px;
            color: #cdd6f4;
            font-size: 15px;
            outline: none;
            transition: border-color 0.2s;
        }
        input[type="password"]:focus {
            border-color: #89b4fa;
        }
        input[type="password"]::placeholder {
            color: #585b70;
        }
        button[type="submit"] {
            width: 100%%;
            padding: 12px;
            margin-top: 20px;
            background: #89b4fa;
            color: #1e1e2e;
            border: none;
            border-radius: 8px;
            font-size: 15px;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s;
        }
        button[type="submit"]:hover {
            background: #74c7ec;
        }
        button[type="submit"]:active {
            background: #89dceb;
        }
    </style>
</head>
<body>
    <div class="login-card">
        <div class="logo">
            <svg fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/>
            </svg>
            <h1>Plugger</h1>
            <p>Enter your API key to continue</p>
        </div>
        %s
        <form method="POST" action="/login">
            <label for="key">API Key</label>
            <input type="password" id="key" name="key" placeholder="pk_..." autofocus autocomplete="off" />
            <button type="submit">Sign in</button>
        </form>
    </div>
</body>
</html>`, errorHTML)
}
