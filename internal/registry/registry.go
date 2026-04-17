// Package registry manages plugin registries — fetching, searching,
// and checking for updates from remote plugin indexes.
package registry

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	OfficialRegistryURL = "https://alexgoller.github.io/illumio-plugger/registry.json"
	OfficialRegistryName = "official"
)

// Registry represents a remote plugin index.
type Registry struct {
	Name    string    `json:"name"`
	URL     string    `json:"url"`
	Updated time.Time `json:"updated"`
	Plugins []Plugin  `json:"plugins"`
}

// Plugin describes an available plugin in the registry.
type Plugin struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	Image       string   `json:"image"`
	Description string   `json:"description"`
	Mode        string   `json:"mode"`
	HasUI       bool     `json:"has_ui"`
	Language    string   `json:"language"`
	Tags        []string `json:"tags"`
	Author      string   `json:"author"`
	Homepage    string   `json:"homepage"`
}

// RepoEntry is a configured registry in the repos file.
type RepoEntry struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

// RepoConfig holds all configured registries.
type RepoConfig struct {
	Repos []RepoEntry `json:"repos"`
}

// Manager handles registry operations.
type Manager struct {
	dataDir string
}

// NewManager creates a registry manager.
func NewManager(dataDir string) *Manager {
	return &Manager{dataDir: dataDir}
}

func (m *Manager) reposPath() string {
	return filepath.Join(m.dataDir, "repos.json")
}

func (m *Manager) cachePath(name string) string {
	return filepath.Join(m.dataDir, "cache", name+".json")
}

// ListRepos returns all configured registries.
func (m *Manager) ListRepos() ([]RepoEntry, error) {
	repos, err := m.loadRepos()
	if err != nil {
		return nil, err
	}
	return repos.Repos, nil
}

// AddRepo adds a custom registry.
func (m *Manager) AddRepo(name, url string) error {
	repos, _ := m.loadRepos()
	for _, r := range repos.Repos {
		if r.Name == name {
			return fmt.Errorf("repo %q already exists", name)
		}
	}
	repos.Repos = append(repos.Repos, RepoEntry{Name: name, URL: url})
	return m.saveRepos(repos)
}

// RemoveRepo removes a custom registry.
func (m *Manager) RemoveRepo(name string) error {
	if name == OfficialRegistryName {
		return fmt.Errorf("cannot remove the official registry")
	}
	repos, _ := m.loadRepos()
	filtered := make([]RepoEntry, 0)
	for _, r := range repos.Repos {
		if r.Name != name {
			filtered = append(filtered, r)
		}
	}
	repos.Repos = filtered
	return m.saveRepos(repos)
}

// FetchAll fetches all configured registries and caches results.
func (m *Manager) FetchAll() ([]Registry, error) {
	repos, _ := m.loadRepos()
	var registries []Registry
	for _, repo := range repos.Repos {
		reg, err := m.fetchRegistry(repo.URL)
		if err != nil {
			continue
		}
		reg.Name = repo.Name
		registries = append(registries, *reg)
		// Cache
		m.cacheRegistry(repo.Name, reg)
	}
	return registries, nil
}

// Search searches all registries for plugins matching a query.
func (m *Manager) Search(query string) ([]Plugin, error) {
	registries, err := m.FetchAll()
	if err != nil {
		return nil, err
	}

	query = strings.ToLower(query)
	var results []Plugin
	for _, reg := range registries {
		for _, p := range reg.Plugins {
			if matches(p, query) {
				results = append(results, p)
			}
		}
	}
	return results, nil
}

// FindPlugin looks up a plugin by name across all registries.
func (m *Manager) FindPlugin(name string) (*Plugin, error) {
	registries, err := m.FetchAll()
	if err != nil {
		return nil, err
	}
	for _, reg := range registries {
		for _, p := range reg.Plugins {
			if p.Name == name {
				return &p, nil
			}
		}
	}
	return nil, fmt.Errorf("plugin %q not found in any registry", name)
}

// CheckUpdates compares installed plugin versions against registry.
func (m *Manager) CheckUpdates(installed map[string]string) ([]UpdateInfo, error) {
	registries, err := m.FetchAll()
	if err != nil {
		return nil, err
	}

	var updates []UpdateInfo
	for _, reg := range registries {
		for _, p := range reg.Plugins {
			installedVersion, ok := installed[p.Name]
			if !ok {
				continue
			}
			if p.Version != installedVersion {
				updates = append(updates, UpdateInfo{
					Name:             p.Name,
					InstalledVersion: installedVersion,
					LatestVersion:    p.Version,
					Image:            p.Image,
					Registry:         reg.Name,
				})
			}
		}
	}
	return updates, nil
}

// UpdateInfo describes an available update.
type UpdateInfo struct {
	Name             string `json:"name"`
	InstalledVersion string `json:"installed_version"`
	LatestVersion    string `json:"latest_version"`
	Image            string `json:"image"`
	Registry         string `json:"registry"`
}

func matches(p Plugin, query string) bool {
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(p.Name), query) {
		return true
	}
	if strings.Contains(strings.ToLower(p.Description), query) {
		return true
	}
	for _, tag := range p.Tags {
		if strings.Contains(strings.ToLower(tag), query) {
			return true
		}
	}
	return false
}

func (m *Manager) loadRepos() (*RepoConfig, error) {
	data, err := os.ReadFile(m.reposPath())
	if err != nil {
		// Default: official registry only
		return &RepoConfig{
			Repos: []RepoEntry{
				{Name: OfficialRegistryName, URL: OfficialRegistryURL},
			},
		}, nil
	}
	var config RepoConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return &RepoConfig{
			Repos: []RepoEntry{
				{Name: OfficialRegistryName, URL: OfficialRegistryURL},
			},
		}, nil
	}
	// Ensure official is always present
	hasOfficial := false
	for _, r := range config.Repos {
		if r.Name == OfficialRegistryName {
			hasOfficial = true
			break
		}
	}
	if !hasOfficial {
		config.Repos = append([]RepoEntry{{Name: OfficialRegistryName, URL: OfficialRegistryURL}}, config.Repos...)
	}
	return &config, nil
}

func (m *Manager) saveRepos(config *RepoConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(m.reposPath(), data, 0600)
}

func (m *Manager) fetchRegistry(url string) (*Registry, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d from %s", resp.StatusCode, url)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var reg Registry
	if err := json.Unmarshal(data, &reg); err != nil {
		return nil, fmt.Errorf("parsing registry: %w", err)
	}
	return &reg, nil
}

func (m *Manager) cacheRegistry(name string, reg *Registry) {
	cacheDir := filepath.Join(m.dataDir, "cache")
	os.MkdirAll(cacheDir, 0755)
	data, err := json.MarshalIndent(reg, "", "  ")
	if err != nil {
		return
	}
	os.WriteFile(m.cachePath(name), data, 0600)
}
