package reports

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/illumio/plugger/internal/config"
)

// OutputStore persists output configurations to a JSON file.
type OutputStore struct {
	path string
	mu   sync.Mutex
}

// NewOutputStore creates a store at the given data directory.
func NewOutputStore(dataDir string) *OutputStore {
	return &OutputStore{
		path: filepath.Join(dataDir, "outputs.json"),
	}
}

// List returns all stored outputs.
func (s *OutputStore) List() ([]config.OutputConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading output store: %w", err)
	}

	var outputs []config.OutputConfig
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("parsing output store: %w", err)
	}
	return outputs, nil
}

// Add adds a new output. Returns error if name already exists.
func (s *OutputStore) Add(o config.OutputConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	outputs, err := s.load()
	if err != nil {
		return err
	}

	for _, existing := range outputs {
		if existing.Name == o.Name {
			return fmt.Errorf("output %q already exists", o.Name)
		}
	}

	outputs = append(outputs, o)
	return s.save(outputs)
}

// Remove removes an output by name.
func (s *OutputStore) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	outputs, err := s.load()
	if err != nil {
		return err
	}

	found := false
	var filtered []config.OutputConfig
	for _, o := range outputs {
		if o.Name == name {
			found = true
			continue
		}
		filtered = append(filtered, o)
	}

	if !found {
		return fmt.Errorf("output %q not found", name)
	}

	return s.save(filtered)
}

func (s *OutputStore) load() ([]config.OutputConfig, error) {
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading output store: %w", err)
	}

	var outputs []config.OutputConfig
	if err := json.Unmarshal(data, &outputs); err != nil {
		return nil, fmt.Errorf("parsing output store: %w", err)
	}
	return outputs, nil
}

func (s *OutputStore) save(outputs []config.OutputConfig) error {
	data, err := json.MarshalIndent(outputs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling outputs: %w", err)
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing output store: %w", err)
	}
	return os.Rename(tmp, s.path)
}

// MergeWithConfig merges stored outputs with config-file outputs.
// Config-file outputs take precedence (by name).
func MergeWithConfig(configOutputs, storedOutputs []config.OutputConfig) []config.OutputConfig {
	seen := make(map[string]bool)
	var merged []config.OutputConfig

	for _, o := range configOutputs {
		seen[o.Name] = true
		merged = append(merged, o)
	}
	for _, o := range storedOutputs {
		if !seen[o.Name] {
			merged = append(merged, o)
		}
	}
	return merged
}
