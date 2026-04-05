package plugin

import (
	"encoding/json"
	"fmt"
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
		return nil, fmt.Errorf("parsing plugin store: %w", err)
	}
	if plugins == nil {
		plugins = make(map[string]*Plugin)
	}
	return plugins, nil
}

func (s *Store) save(plugins map[string]*Plugin) error {
	data, err := json.MarshalIndent(plugins, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling plugin store: %w", err)
	}

	// Atomic write: write to temp file, then rename
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing plugin store: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("renaming plugin store: %w", err)
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
