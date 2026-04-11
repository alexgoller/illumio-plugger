package dashboard

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"

	"github.com/illumio/plugger/internal/scheduler"
)

// EventRegistry holds registered event-mode plugins and dispatches incoming events.
type EventRegistry struct {
	mu         sync.RWMutex
	schedulers map[string]*scheduler.EventScheduler // plugin name -> scheduler
	token      string                                // webhook auth token
}

// NewEventRegistry creates an event registry with the given auth token.
// If token is empty, a random one is generated and logged.
func NewEventRegistry(token string) *EventRegistry {
	if token == "" {
		b := make([]byte, 16)
		rand.Read(b)
		token = hex.EncodeToString(b)
		slog.Info("generated webhook token (use this in pce-events config)", "token", token)
	}
	return &EventRegistry{
		schedulers: make(map[string]*scheduler.EventScheduler),
		token:      token,
	}
}

// Register adds an event scheduler to the registry.
func (r *EventRegistry) Register(name string, s *scheduler.EventScheduler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.schedulers[name] = s
}

// Token returns the webhook authentication token.
func (r *EventRegistry) Token() string {
	return r.token
}

// handleEventTrigger receives webhook POSTs and dispatches to matching event plugins.
//
// Authentication: requires Bearer token in Authorization header or ?token= query param.
//
// Request body:
//
//	{
//	    "event_type": "workload.create",
//	    ... (full event payload passed to container as PLUGGER_EVENT_PAYLOAD)
//	}
//
// Response:
//
//	{
//	    "triggered": ["plugin-a", "plugin-b"],
//	    "skipped": ["plugin-c"],
//	    "errors": {"plugin-d": "concurrency limit"}
//	}
func (h *Handler) handleEventTrigger(w http.ResponseWriter, r *http.Request) {
	if h.events == nil {
		http.Error(w, "Event system not initialized", http.StatusServiceUnavailable)
		return
	}

	// Authenticate
	if !h.authenticateWebhook(r) {
		http.Error(w, "Unauthorized — provide Bearer token or ?token= query param", http.StatusUnauthorized)
		return
	}

	// Read body
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 1MB limit
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Extract event_type from payload
	var envelope struct {
		EventType string `json:"event_type"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if envelope.EventType == "" {
		http.Error(w, "Missing event_type field", http.StatusBadRequest)
		return
	}

	slog.Info("webhook received", "event_type", envelope.EventType)

	// Dispatch to matching plugins
	triggered := []string{}
	skipped := []string{}
	errors := map[string]string{}

	h.events.mu.RLock()
	defer h.events.mu.RUnlock()

	for name, sched := range h.events.schedulers {
		if !sched.MatchesEvent(envelope.EventType) {
			skipped = append(skipped, name)
			continue
		}

		if err := sched.Trigger(json.RawMessage(body)); err != nil {
			errors[name] = err.Error()
			slog.Warn("event trigger failed", "plugin", name, "error", err)
		} else {
			triggered = append(triggered, name)
		}
	}

	slog.Info("event dispatched", "event_type", envelope.EventType,
		"triggered", len(triggered), "skipped", len(skipped), "errors", len(errors))

	h.json(w, http.StatusOK, map[string]any{
		"event_type": envelope.EventType,
		"triggered":  triggered,
		"skipped":    skipped,
		"errors":     errors,
	})
}

// handleEventStats returns statistics for all event schedulers.
func (h *Handler) handleEventStats(w http.ResponseWriter, r *http.Request) {
	if h.events == nil {
		h.json(w, http.StatusOK, map[string]any{"plugins": map[string]any{}})
		return
	}

	h.events.mu.RLock()
	defer h.events.mu.RUnlock()

	stats := map[string]any{}
	for name, sched := range h.events.schedulers {
		stats[name] = sched.Stats()
	}

	h.json(w, http.StatusOK, map[string]any{
		"plugins": stats,
		"token":   h.events.token,
	})
}

func (h *Handler) authenticateWebhook(r *http.Request) bool {
	if h.events == nil || h.events.token == "" {
		return true
	}

	// Check Authorization: Bearer <token>
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		provided := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(provided), []byte(h.events.token)) == 1 {
			return true
		}
	}

	// Check ?token= query param
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		if subtle.ConstantTimeCompare([]byte(qToken), []byte(h.events.token)) == 1 {
			return true
		}
	}

	return false
}
