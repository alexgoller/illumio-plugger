package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

type PluginManifest struct {
	APIVersion string          `yaml:"apiVersion"`
	Name       string          `yaml:"name"`
	Version    string          `yaml:"version"`
	Image      string          `yaml:"image"`
	Schedule   ScheduleConfig  `yaml:"schedule"`
	Env        []EnvVar        `yaml:"env"`
	Events     *EventConfig    `yaml:"events,omitempty"`
	Health     *HealthConfig   `yaml:"health,omitempty"`
	Resources  *ResourceConfig `yaml:"resources,omitempty"`
}

type ScheduleConfig struct {
	Mode string `yaml:"mode"` // daemon, cron, event
	Cron string `yaml:"cron,omitempty"`
}

type EnvVar struct {
	Name     string `yaml:"name"`
	Required bool   `yaml:"required"`
	Default  string `yaml:"default,omitempty"`
	Secret   bool   `yaml:"secret,omitempty"`
}

type EventConfig struct {
	Types  []string `yaml:"types"`
	Filter string   `yaml:"filter,omitempty"`
}

type HealthConfig struct {
	Endpoint string        `yaml:"endpoint,omitempty"`
	Port     int           `yaml:"port,omitempty"`
	Interval time.Duration `yaml:"interval"`
	Timeout  time.Duration `yaml:"timeout"`
	Retries  int           `yaml:"retries"`
}

type ResourceConfig struct {
	MemoryLimit string `yaml:"memoryLimit,omitempty"`
	CPULimit    string `yaml:"cpuLimit,omitempty"`
}

// LoadManifest reads and validates a plugin manifest from a YAML file.
func LoadManifest(path string) (*PluginManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading manifest %s: %w", path, err)
	}

	var m PluginManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest %s: %w", path, err)
	}

	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest %s: %w", path, err)
	}

	return &m, nil
}

// LoadManifestFromBytes parses and validates a manifest from raw YAML bytes.
func LoadManifestFromBytes(data []byte) (*PluginManifest, error) {
	var m PluginManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing manifest: %w", err)
	}
	if err := m.Validate(); err != nil {
		return nil, fmt.Errorf("invalid manifest: %w", err)
	}
	return &m, nil
}

// Validate checks that the manifest has all required fields.
func (m *PluginManifest) Validate() error {
	if m.Name == "" {
		return fmt.Errorf("name is required")
	}
	if m.Image == "" {
		return fmt.Errorf("image is required")
	}
	if m.Version == "" {
		return fmt.Errorf("version is required")
	}

	switch m.Schedule.Mode {
	case "daemon", "cron", "event":
	case "":
		return fmt.Errorf("schedule.mode is required (daemon, cron, or event)")
	default:
		return fmt.Errorf("schedule.mode must be daemon, cron, or event, got %q", m.Schedule.Mode)
	}

	if m.Schedule.Mode == "cron" && m.Schedule.Cron == "" {
		return fmt.Errorf("schedule.cron is required when mode is cron")
	}

	if m.Schedule.Mode == "event" {
		if m.Events == nil || len(m.Events.Types) == 0 {
			return fmt.Errorf("events.types is required when mode is event")
		}
	}

	return nil
}
