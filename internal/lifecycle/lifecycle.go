// Package lifecycle contains shared plugin start/stop/restart logic
// used by both CLI commands and the dashboard HTTP handlers.
package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/illumio/plugger/internal/config"
	ct "github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
)

// Deps holds the shared dependencies needed for plugin lifecycle operations.
type Deps struct {
	Store   *plugin.Store
	Runtime ct.Runtime
	Config  *config.Config
}

// StartPlugin creates and starts a container for the given plugin.
func StartPlugin(ctx context.Context, d *Deps, p *plugin.Plugin) error {
	if err := ct.SetupNetwork(ctx, d.Runtime, d.Config.Plugger.Network); err != nil {
		return err
	}

	env := p.BuildEnv(d.Config.PCE)
	labels := map[string]string{
		ct.LabelManaged: "true",
		ct.LabelPlugin:  p.Name,
		ct.LabelVersion: p.Manifest.Version,
		ct.LabelMode:    p.Manifest.Schedule.Mode,
	}

	var memory int64
	if p.Manifest.Resources != nil {
		memory = parseMemory(p.Manifest.Resources.MemoryLimit)
	}
	var cpus string
	if p.Manifest.Resources != nil {
		cpus = p.Manifest.Resources.CPULimit
	}

	// Build port mappings from discovered metadata
	var ports []ct.PortMapping
	if p.Metadata != nil {
		for _, ps := range p.Metadata.Ports {
			ports = append(ports, ct.PortMapping{
				ContainerPort: ps.Port,
				HostPort:      0,
				Protocol:      ps.Protocol,
			})
		}
	}

	// Build volume mounts from discovered metadata
	var volumes []ct.VolumeMount
	if p.Metadata != nil {
		for _, vs := range p.Metadata.Volumes {
			hostDir := filepath.Join(d.Config.Plugger.DataDir, "volumes", p.Name, filepath.Base(vs.Path))
			if err := os.MkdirAll(hostDir, 0755); err != nil {
				return fmt.Errorf("creating volume dir %s: %w", hostDir, err)
			}
			volumes = append(volumes, ct.VolumeMount{
				HostPath:      hostDir,
				ContainerPath: vs.Path,
			})
		}
	}

	// Merge config defaults from metadata into env
	if p.Metadata != nil {
		for _, c := range p.Metadata.Config {
			if c.Default != "" {
				found := false
				prefix := c.Name + "="
				for _, existing := range env {
					if len(existing) >= len(prefix) && existing[:len(prefix)] == prefix {
						found = true
						break
					}
				}
				if !found {
					env = append(env, c.Name+"="+c.Default)
				}
			}
		}
	}

	containerID, err := d.Runtime.Create(ctx, ct.CreateOpts{
		Name:    p.ContainerName(),
		Image:   p.Manifest.Image,
		Env:     env,
		Network: d.Config.Plugger.Network,
		Labels:  labels,
		Memory:  memory,
		CPUs:    cpus,
		Ports:   ports,
		Volumes: volumes,
	})
	if err != nil {
		return fmt.Errorf("creating container: %w", err)
	}

	if err := d.Runtime.Start(ctx, containerID); err != nil {
		_ = d.Runtime.Remove(ctx, containerID)
		return fmt.Errorf("starting container: %w", err)
	}

	hostPorts := make(map[int]int)
	for _, pm := range ports {
		hostPorts[pm.ContainerPort] = pm.HostPort
	}

	now := time.Now()
	p.ContainerID = containerID
	p.State = plugin.StateRunning
	p.LastStarted = &now
	p.LastError = ""
	p.HostPorts = hostPorts

	if err := d.Store.Put(p); err != nil {
		return fmt.Errorf("updating plugin state: %w", err)
	}

	slog.Info("plugin started", "name", p.Name, "container", containerID[:12])
	return nil
}

// StopPlugin stops a running plugin's container and updates state.
func StopPlugin(ctx context.Context, d *Deps, p *plugin.Plugin) error {
	if p.ContainerID != "" {
		if err := d.Runtime.Stop(ctx, p.ContainerID, 10*time.Second); err != nil {
			slog.Warn("error stopping container", "plugin", p.Name, "error", err)
		}
		if err := d.Runtime.Remove(ctx, p.ContainerID); err != nil {
			slog.Warn("error removing container", "plugin", p.Name, "error", err)
		}
	}

	now := time.Now()
	p.State = plugin.StateStopped
	p.LastStopped = &now
	p.ContainerID = ""

	if err := d.Store.Put(p); err != nil {
		return fmt.Errorf("updating plugin state: %w", err)
	}

	slog.Info("plugin stopped", "name", p.Name)
	return nil
}

// RestartPlugin stops then starts a plugin.
func RestartPlugin(ctx context.Context, d *Deps, p *plugin.Plugin) error {
	if p.State == plugin.StateRunning && p.ContainerID != "" {
		if err := d.Runtime.Stop(ctx, p.ContainerID, 10*time.Second); err != nil {
			slog.Warn("error stopping container", "plugin", p.Name, "error", err)
		}
		_ = d.Runtime.Remove(ctx, p.ContainerID)
	}
	return StartPlugin(ctx, d, p)
}

func parseMemory(s string) int64 {
	if s == "" {
		return 0
	}
	n := int64(0)
	multiplier := int64(1)
	for i, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int64(c-'0')
		} else {
			switch s[i:] {
			case "k", "K":
				multiplier = 1024
			case "m", "M":
				multiplier = 1024 * 1024
			case "g", "G":
				multiplier = 1024 * 1024 * 1024
			}
			break
		}
	}
	return n * multiplier
}
