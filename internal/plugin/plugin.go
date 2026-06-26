package plugin

import (
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/config"
)

// State represents the lifecycle state of a plugin.
type State string

const (
	StateInstalled State = "installed"
	StateStarting  State = "starting"
	StateRunning   State = "running"
	StateStopped   State = "stopped"
	StateErrored   State = "errored"
)

// Plugin represents an installed plugin and its runtime state.
type Plugin struct {
	Name         string                    `json:"name"`
	Manifest     config.PluginManifest     `json:"manifest"`
	Metadata     *config.ContainerMetadata `json:"metadata,omitempty"`
	State        State                     `json:"state"`
	ContainerID  string                    `json:"containerId,omitempty"`
	Enabled      bool                      `json:"enabled"`
	EnvOverrides map[string]string         `json:"envOverrides,omitempty"`
	HostPorts    map[int]int               `json:"hostPorts,omitempty"` // containerPort -> hostPort
	InstalledAt  time.Time                 `json:"installedAt"`
	LastStarted  *time.Time                `json:"lastStarted,omitempty"`
	LastStopped  *time.Time                `json:"lastStopped,omitempty"`
	LastError    string                    `json:"lastError,omitempty"`
	LastExitCode *int                      `json:"lastExitCode,omitempty"`
	NextRun      *time.Time                `json:"nextRun,omitempty"`
}

// ContainerName returns the deterministic Docker container name for this plugin.
func (p *Plugin) ContainerName() string {
	return "plugger-" + p.Name
}

// PluggerEnvConfig holds framework-level env vars injected into every container.
type PluggerEnvConfig struct {
	PluggerURL   string
	WebhookToken string
}

// BuildEnv constructs the full environment variable list for the container,
// layering PCE config, plugger framework vars, manifest defaults, and user overrides.
func (p *Plugin) BuildEnv(pce config.PCEConfig, pe PluggerEnvConfig) []string {
	env := []string{
		"PCE_HOST=" + pce.Host,
		"PCE_PORT=" + itoa(pce.Port),
		"PCE_ORG_ID=" + itoa(pce.OrgID),
		"PCE_API_KEY=" + pce.APIKey,
		"PCE_API_SECRET=" + pce.APISecret,
		"PLUGGER_PLUGIN_NAME=" + p.Name,
		// Disable stdout/stderr block-buffering so Python (and similar) plugins
		// stream logs in real time to `docker logs` / `plugger logs` instead of
		// holding them in a buffer until the process exits.
		"PYTHONUNBUFFERED=1",
	}

	if pe.PluggerURL != "" {
		env = append(env, "PLUGGER_URL="+pe.PluggerURL)
	}
	if pe.WebhookToken != "" {
		env = append(env, "PLUGGER_WEBHOOK_TOKEN="+pe.WebhookToken)
	}

	// Layer manifest defaults
	for _, e := range p.Manifest.Env {
		if e.Default != "" {
			env = append(env, e.Name+"="+e.Default)
		}
	}

	// Layer user overrides (overwrites defaults)
	for k, v := range p.EnvOverrides {
		env = append(env, k+"="+v)
	}

	return env
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}
