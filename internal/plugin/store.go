package plugin

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

// Store provides persistent storage for plugin state backed by a JSON file.
type Store struct {
	path string
	mu   sync.Mutex
}

// NewStore creates a store that persists to the given file path.
func NewStore(dataDir string) *Store {
	return &Store{
		path: filepath.Join(dataDir, "plugins.json"),
	}
}

func (s *Store) load() (map[string]*Plugin, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]*Plugin), nil
		}
		return nil, fmt.Errorf("reading plugin store: %w", err)
	}

	var plugins map[string]*Plugin
	if err := json.Unmarshal(data, &plugins); err != nil {
		// Try to recover from corrupt JSON by loading the backup
		slog.Warn("plugin store corrupt, attempting recovery from backup", "error", err)
		backup := s.path + ".bak"
		bakData, bakErr := os.ReadFile(backup)
		if bakErr != nil {
			return nil, fmt.Errorf("parsing plugin store (no backup available): %w", err)
		}
		if bakErr := json.Unmarshal(bakData, &plugins); bakErr != nil {
			return nil, fmt.Errorf("parsing plugin store (backup also corrupt): %w", err)
		}
		slog.Info("recovered plugin store from backup", "plugins", len(plugins))
		// Restore the good backup as the primary
		_ = s.atomicWrite(s.path, bakData)
	}
	if plugins == nil {
		plugins = make(map[string]*Plugin)
	}
	return plugins, nil
}

// atomicWrite writes data to path using write-fsync-rename for crash safety.
func (s *Store) atomicWrite(path string, data []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}

	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("writing temp file: %w", err)
	}

	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("syncing temp file: %w", err)
	}
	f.Close()

	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("renaming temp file: %w", err)
	}
	return nil
}

func (s *Store) save(plugins map[string]*Plugin) error {
	data, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling plugin store: %w", err)
	}

	// Keep a backup of the last known-good state before overwriting
	if existing, err := os.ReadFile(s.path); err == nil {
		_ = s.atomicWrite(s.path+".bak", existing)
	}

	// Acquire a file lock to protect against concurrent plugger instances
	lockPath := s.path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("creating lock file: %w", err)
	}
	defer lockFile.Close()
	defer os.Remove(lockPath)

	if err := lockFileExclusive(lockFile); err != nil {
		return fmt.Errorf("acquiring store lock: %w", err)
	}
	defer unlockFile(lockFile)

	if err := s.atomicWrite(s.path, data); err != nil {
		return fmt.Errorf("writing plugin store: %w", err)
	}
	return nil
}

// Get returns a plugin by name.
func (s *Store) Get(name string) (*Plugin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plugins, err := s.load()
	if err != nil {
		return nil, err
	}

	p, ok := plugins[name]
	if !ok {
		return nil, fmt.Errorf("plugin %q not found", name)
	}
	return p, nil
}

// Put saves or updates a plugin.
func (s *Store) Put(p *Plugin) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plugins, err := s.load()
	if err != nil {
		return err
	}

	plugins[p.Name] = p
	return s.save(plugins)
}

// Delete removes a plugin by name.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	plugins, err := s.load()
	if err != nil {
		return err
	}

	if _, ok := plugins[name]; !ok {
		return fmt.Errorf("plugin %q not found", name)
	}

	delete(plugins, name)
	return s.save(plugins)
}

// List returns all plugins sorted by name.
func (s *Store) List() ([]*Plugin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	plugins, err := s.load()
	if err != nil {
		return nil, err
	}

	result := make([]*Plugin, 0, len(plugins))
	for _, p := range plugins {
		result = append(result, p)
	}

	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})

	return result, nil
}
