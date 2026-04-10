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

// BuildEnv constructs the full environment variable list for the container,
// layering PCE config, manifest defaults, and user overrides.
func (p *Plugin) BuildEnv(pce config.PCEConfig) []string {
	env := []string{
		"PCE_HOST=" + pce.Host,
		"PCE_PORT=" + itoa(pce.Port),
		"PCE_ORG_ID=" + itoa(pce.OrgID),
		"PCE_API_KEY=" + pce.APIKey,
		"PCE_API_SECRET=" + pce.APISecret,
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
