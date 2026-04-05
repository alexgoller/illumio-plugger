package config

import (
	"fmt"
	"time"

	"gopkg.in/yaml.v3"
)

// ContainerMetadata is the in-container metadata file (/.plugger/metadata.yaml)
// that plugin authors include in their Docker images. Plugger discovers this
// after pulling the image to learn about ports, config, volumes, and plugin info.
type ContainerMetadata struct {
	Plugger     string        `yaml:"plugger"`               // schema version, e.g. "v1"
	Ports       []PortSpec    `yaml:"ports,omitempty"`
	Config      []ConfigSpec  `yaml:"config,omitempty"`
	Volumes     []VolumeSpec  `yaml:"volumes,omitempty"`
	Info        *PluginInfo   `yaml:"info,omitempty"`
	HealthCheck *HealthSpec   `yaml:"healthcheck,omitempty"`
}

// PortSpec declares a port the plugin container exposes.
type PortSpec struct {
	Port        int    `yaml:"port"`
	Protocol    string `yaml:"protocol,omitempty"`    // tcp (default) or udp
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Type        string `yaml:"type,omitempty"`         // ui, api, service, metrics
	Path        string `yaml:"path,omitempty"`         // base path for ui/api
}

// ConfigSpec declares a configuration variable the plugin requires.
type ConfigSpec struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required"`
	Type        string `yaml:"type,omitempty"`         // string, int, bool, secret
	Default     string `yaml:"default,omitempty"`
	Example     string `yaml:"example,omitempty"`
	Validation  string `yaml:"validation,omitempty"`   // regex pattern
}

// VolumeSpec declares a volume mount the plugin needs.
type VolumeSpec struct {
	Path        string `yaml:"path"`
	Description string `yaml:"description,omitempty"`
	Required    bool   `yaml:"required"`
}

// PluginInfo contains display metadata about the plugin.
type PluginInfo struct {
	Title       string `yaml:"title"`
	Description string `yaml:"description,omitempty"`
	Author      string `yaml:"author,omitempty"`
	License     string `yaml:"license,omitempty"`
	Homepage    string `yaml:"homepage,omitempty"`
	Icon        string `yaml:"icon,omitempty"`
}

// HealthSpec overrides health check settings discovered from the container.
type HealthSpec struct {
	Endpoint string        `yaml:"endpoint"`
	Port     int           `yaml:"port"`
	Interval time.Duration `yaml:"interval,omitempty"`
}

// ParseMetadata parses in-container metadata from raw YAML bytes.
func ParseMetadata(data []byte) (*ContainerMetadata, error) {
	var m ContainerMetadata
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing container metadata: %w", err)
	}

	// Set defaults
	for i := range m.Ports {
		if m.Ports[i].Protocol == "" {
			m.Ports[i].Protocol = "tcp"
		}
	}

	return &m, nil
}
