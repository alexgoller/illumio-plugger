package lifecycle

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/illumio/plugger/internal/config"
	ct "github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/illumio/plugger/internal/registry"
)

// ExtractManifestFromImage reads the plugger manifest and (optional) metadata
// out of a built image. Mirrors what `plugger install` does at install time.
func ExtractManifestFromImage(ctx context.Context, rt ct.Runtime, image string) (*config.PluginManifest, *config.ContainerMetadata, error) {
	manifestBytes, err := rt.CopyFromImage(ctx, image, "/.plugger/manifest.yaml")
	if err != nil {
		manifestBytes, err = rt.CopyFromImage(ctx, image, "/.plugger/plugin.yaml")
	}
	if err != nil {
		return nil, nil, fmt.Errorf("image %s has no /.plugger/manifest.yaml or /.plugger/plugin.yaml", image)
	}

	manifest, err := config.LoadManifestFromBytes(manifestBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing manifest: %w", err)
	}

	var metadata *config.ContainerMetadata
	if metadataBytes, mdErr := rt.CopyFromImage(ctx, image, "/.plugger/metadata.yaml"); mdErr == nil {
		metadata, _ = config.ParseMetadata(metadataBytes)
	}

	return manifest, metadata, nil
}

// PrepareReinstall resolves a plugin in the registry, pulls the latest image,
// re-extracts its manifest and metadata, and writes the refreshed manifest to
// the store — preserving the user's env overrides and enabled state. It does
// NOT stop or start any container; the caller decides how to (re)start so the
// daemon scheduler stays the single owner of the container lifecycle.
//
// Returns whether the plugin was running before the update, plus the old and
// new versions for reporting.
func PrepareReinstall(ctx context.Context, d *Deps, name string) (wasRunning bool, oldVersion, newVersion string, err error) {
	p, err := d.Store.Get(name)
	if err != nil {
		return false, "", "", fmt.Errorf("plugin %q not installed", name)
	}
	oldVersion = p.Manifest.Version
	wasRunning = p.State == plugin.StateRunning

	mgr := registry.NewManager(d.Config.Plugger.DataDir)
	regPlugin, err := mgr.FindPlugin(name)
	if err != nil {
		return wasRunning, oldVersion, "", fmt.Errorf("not found in registry: %w", err)
	}

	if err := d.Runtime.Pull(ctx, regPlugin.Image); err != nil {
		return wasRunning, oldVersion, "", fmt.Errorf("pulling image: %w", err)
	}

	manifest, metadata, err := ExtractManifestFromImage(ctx, d.Runtime, regPlugin.Image)
	if err != nil {
		return wasRunning, oldVersion, "", err
	}
	// The registry is authoritative for the image reference.
	manifest.Image = regPlugin.Image
	newVersion = manifest.Version

	// Replace the manifest/metadata; EnvOverrides and Enabled live on p and are
	// preserved across the swap.
	p.Manifest = *manifest
	if metadata != nil {
		p.Metadata = metadata
	}
	if err := d.Store.Put(p); err != nil {
		return wasRunning, oldVersion, newVersion, fmt.Errorf("saving plugin: %w", err)
	}

	return wasRunning, oldVersion, newVersion, nil
}

// ReinstallFromRegistry does a full reinstall and restarts the plugin itself if
// it was running. Use this from the CLI or when no daemon scheduler owns the
// plugin. Inside the running daemon, prefer PrepareReinstall + the scheduler's
// restart trigger to avoid racing the watch loop.
func ReinstallFromRegistry(ctx context.Context, d *Deps, name string) (oldVersion, newVersion string, err error) {
	wasRunning, oldVersion, newVersion, err := PrepareReinstall(ctx, d, name)
	if err != nil {
		return oldVersion, newVersion, err
	}

	p, err := d.Store.Get(name)
	if err != nil {
		return oldVersion, newVersion, err
	}

	if wasRunning {
		if err := StopPlugin(ctx, d, p); err != nil {
			slog.Warn("error stopping during reinstall", "plugin", name, "error", err)
		}
		if err := StartPlugin(ctx, d, p); err != nil {
			return oldVersion, newVersion, fmt.Errorf("starting new version: %w", err)
		}
	}

	return oldVersion, newVersion, nil
}
