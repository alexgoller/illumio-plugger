package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// PCE connection details are injected by plugger as environment variables.
type PCEConfig struct {
	Host      string
	Port      string
	OrgID     string
	APIKey    string
	APISecret string
}

func loadPCEConfig() PCEConfig {
	return PCEConfig{
		Host:      os.Getenv("PCE_HOST"),
		Port:      os.Getenv("PCE_PORT"),
		OrgID:     os.Getenv("PCE_ORG_ID"),
		APIKey:    os.Getenv("PCE_API_KEY"),
		APISecret: os.Getenv("PCE_API_SECRET"),
	}
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	log.Println("Starting plugin...")

	pce := loadPCEConfig()
	log.Printf("PCE: %s:%s (org %s)", pce.Host, pce.Port, pce.OrgID)

	// Read plugin-specific config from env
	setting := os.Getenv("MY_PLUGIN_SETTING")
	log.Printf("MY_PLUGIN_SETTING: %s", setting)

	// Set up HTTP server for health checks and UI
	mux := http.NewServeMux()

	// Health check endpoint
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "healthy"})
	})

	// Plugin UI / dashboard
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>My Plugin</title></head>
<body>
  <h1>My Plugin Dashboard</h1>
  <p>PCE: %s:%s (org %s)</p>
  <p>Status: Running</p>
  <p>Setting: %s</p>
</body>
</html>`, pce.Host, pce.Port, pce.OrgID, setting)
	})

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	// Start HTTP server in background
	go func() {
		log.Printf("HTTP server listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	// =====================================================
	// YOUR PLUGIN LOGIC GOES HERE
	// =====================================================
	//
	// For a daemon plugin: run a loop that periodically does work
	// For a cron plugin: do the work once and exit
	// For an event plugin: read PLUGGER_EVENT_PAYLOAD and process it
	//
	// Example: periodic work loop
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()

		for {
			log.Println("Doing periodic work...")
			// TODO: Call PCE API, process data, etc.
			// Example: GET https://{pce.Host}:{pce.Port}/api/v2/orgs/{pce.OrgID}/workloads
			<-ticker.C
		}
	}()

	// Wait for shutdown signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	log.Println("Shutting down...")

	// Graceful HTTP shutdown
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("HTTP shutdown error: %v", err)
	}

	log.Println("Plugin stopped.")
}
