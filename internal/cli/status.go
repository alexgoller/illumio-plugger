package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status [plugin]",
		Short: "Show plugger overview or detailed plugin status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return showOverview()
			}
			return showPluginStatus(args[0])
		},
	}
}

func showOverview() error {
	plugins, err := app.Store.List()
	if err != nil {
		return err
	}

	// Count states
	var total, running, stopped, errored, installed int
	var daemons, crons, events int
	total = len(plugins)
	for _, p := range plugins {
		switch p.State {
		case plugin.StateRunning:
			running++
		case plugin.StateStopped:
			stopped++
		case plugin.StateErrored:
			errored++
		default:
			installed++
		}
		switch p.Manifest.Schedule.Mode {
		case "daemon":
			daemons++
		case "cron":
			crons++
		case "event":
			events++
		}
	}

	// Check live containers
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	managed, _ := app.Runtime.ListManaged(ctx)
	liveContainers := len(managed)

	// PCE config
	pce := app.Config.PCE
	pceStatus := "not configured"
	if pce.Host != "" {
		pceStatus = fmt.Sprintf("%s:%d (org %d)", pce.Host, pce.Port, pce.OrgID)
	}

	fmt.Println("Plugger Status")
	fmt.Println("==============")
	fmt.Printf("\nPCE:          %s\n", pceStatus)
	fmt.Printf("Data Dir:     %s\n", app.Config.Plugger.DataDir)
	fmt.Printf("Network:      %s\n", app.Config.Plugger.Network)

	fmt.Printf("\nPlugins:      %d total\n", total)
	fmt.Printf("  Running:    %d\n", running)
	if stopped > 0 {
		fmt.Printf("  Stopped:    %d\n", stopped)
	}
	if errored > 0 {
		fmt.Printf("  Errored:    %d\n", errored)
	}
	if installed > 0 {
		fmt.Printf("  Installed:  %d\n", installed)
	}

	fmt.Printf("\nSchedule Modes:\n")
	if daemons > 0 {
		fmt.Printf("  Daemon:     %d\n", daemons)
	}
	if crons > 0 {
		fmt.Printf("  Cron:       %d\n", crons)
	}
	if events > 0 {
		fmt.Printf("  Event:      %d\n", events)
	}

	fmt.Printf("\nContainers:   %d live\n", liveContainers)

	// Show each plugin summary
	if total > 0 {
		fmt.Printf("\n%-24s %-10s %-8s %-10s %s\n", "PLUGIN", "VERSION", "MODE", "STATE", "STARTED")
		fmt.Printf("%-24s %-10s %-8s %-10s %s\n", "------", "-------", "----", "-----", "-------")
		for _, p := range plugins {
			started := "—"
			if p.LastStarted != nil {
				d := time.Since(*p.LastStarted)
				if d < time.Hour {
					started = fmt.Sprintf("%dm ago", int(d.Minutes()))
				} else if d < 24*time.Hour {
					started = fmt.Sprintf("%dh ago", int(d.Hours()))
				} else {
					started = fmt.Sprintf("%dd ago", int(d.Hours()/24))
				}
			}
			state := string(p.State)
			if p.LastError != "" && p.State == plugin.StateErrored {
				state = "ERRORED"
			}
			fmt.Printf("%-24s %-10s %-8s %-10s %s\n", p.Name, p.Manifest.Version, p.Manifest.Schedule.Mode, state, started)
		}
	}

	return nil
}

func showPluginStatus(name string) error {
	p, err := app.Store.Get(name)
	if err != nil {
		return err
	}

	fmt.Printf("Plugin:    %s\n", p.Name)
	fmt.Printf("Version:   %s\n", p.Manifest.Version)
	fmt.Printf("Image:     %s\n", p.Manifest.Image)
	fmt.Printf("Mode:      %s\n", p.Manifest.Schedule.Mode)
	fmt.Printf("State:     %s\n", p.State)
	fmt.Printf("Enabled:   %v\n", p.Enabled)
	fmt.Printf("Installed: %s\n", p.InstalledAt.Format(time.RFC3339))

	if p.LastStarted != nil {
		fmt.Printf("Started:   %s\n", p.LastStarted.Format(time.RFC3339))
	}
	if p.LastStopped != nil {
		fmt.Printf("Stopped:   %s\n", p.LastStopped.Format(time.RFC3339))
	}
	if p.LastError != "" {
		fmt.Printf("Error:     %s\n", p.LastError)
	}

	// Show live container info if running
	if p.ContainerID != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		info, err := app.Runtime.Inspect(ctx, p.ContainerID)
		if err == nil {
			fmt.Printf("\nContainer:\n")
			fmt.Printf("  ID:      %s\n", info.ID[:12])
			fmt.Printf("  Status:  %s\n", info.Status)
			fmt.Printf("  Running: %v\n", info.Running)
			if len(info.Ports) > 0 {
				fmt.Printf("  Ports:  ")
				first := true
				for container, host := range info.Ports {
					if !first {
						fmt.Printf(", ")
					}
					fmt.Printf("%d->%d", container, host)
					first = false
				}
				fmt.Println()
			}
		}
	}

	// Show plugin info from container metadata
	if p.Metadata != nil {
		if p.Metadata.Info != nil {
			fmt.Printf("\nPlugin Info:\n")
			fmt.Printf("  Title:   %s\n", p.Metadata.Info.Title)
			if p.Metadata.Info.Description != "" {
				fmt.Printf("  About:   %s\n", p.Metadata.Info.Description)
			}
			if p.Metadata.Info.Author != "" {
				fmt.Printf("  Author:  %s\n", p.Metadata.Info.Author)
			}
			if p.Metadata.Info.License != "" {
				fmt.Printf("  License: %s\n", p.Metadata.Info.License)
			}
			if p.Metadata.Info.Homepage != "" {
				fmt.Printf("  URL:     %s\n", p.Metadata.Info.Homepage)
			}
		}

		if len(p.Metadata.Ports) > 0 {
			fmt.Printf("\nPorts:\n")
			for _, ps := range p.Metadata.Ports {
				hostPort := ps.Port
				if hp, ok := p.HostPorts[ps.Port]; ok && hp > 0 {
					hostPort = hp
				}
				if ps.Type == "ui" || ps.Type == "api" {
					path := ps.Path
					if path == "" {
						path = "/"
					}
					fmt.Printf("  %s: http://localhost:%d%s (%d/%s)\n", ps.Name, hostPort, path, ps.Port, ps.Protocol)
				} else {
					fmt.Printf("  %s: localhost:%d -> %d/%s\n", ps.Name, hostPort, ps.Port, ps.Protocol)
				}
			}
		}

		if len(p.Metadata.Volumes) > 0 {
			fmt.Printf("\nVolumes:\n")
			for _, v := range p.Metadata.Volumes {
				req := ""
				if v.Required {
					req = " (required)"
				}
				fmt.Printf("  %s — %s%s\n", v.Path, v.Description, req)
			}
		}

		if len(p.Metadata.Config) > 0 {
			fmt.Printf("\nDiscovered Config:\n")
			for _, c := range p.Metadata.Config {
				val := c.Default
				if override, ok := p.EnvOverrides[c.Name]; ok {
					val = override
				}
				if c.Type == "secret" {
					val = "***"
				}
				req := ""
				if c.Required {
					req = " (required)"
				}
				fmt.Printf("  %s=%s%s\n", c.Name, val, req)
				if c.Description != "" {
					fmt.Printf("    %s\n", c.Description)
				}
			}
		}
	}

	// Show env vars (mask secrets)
	if len(p.Manifest.Env) > 0 {
		fmt.Printf("\nEnvironment:\n")
		for _, e := range p.Manifest.Env {
			val := e.Default
			if override, ok := p.EnvOverrides[e.Name]; ok {
				val = override
			}
			if e.Secret {
				val = "***"
			}
			req := ""
			if e.Required {
				req = " (required)"
			}
			fmt.Printf("  %s=%s%s\n", e.Name, val, req)
		}
	}

	return nil
}
