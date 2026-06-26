package lifecycle

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/illumio/plugger/internal/config"
)

// staleConfig mimics a pce-events config.yaml written by an older plugger that
// predates the pce_port / pce_timeout keys.
const staleConfig = `config:
  pce: poc3.illum.io
  pce_api_user: api_x
  pce_api_secret: secret_x
  pce_org: 3998508
  pce_poll_interval: 60
  httpd: true
watchers:
  .*:
  - status: '*'
    plugin: PCEStdout
`

func depsWithPort(port int) *Deps {
	return &Deps{Config: &config.Config{PCE: config.PCEConfig{Port: port}}}
}

func TestMigratePCEEventsConfig_AddsMissingKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(staleConfig), 0600); err != nil {
		t.Fatal(err)
	}

	migratePCEEventsConfig(path, staleConfig, depsWithPort(443))

	out, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(out)

	if !strings.Contains(got, "pce_timeout: 120") {
		t.Errorf("expected pce_timeout to be added; got:\n%s", got)
	}
	if !strings.Contains(got, "pce_port: 443") {
		t.Errorf("expected pce_port to be added; got:\n%s", got)
	}
	// User content must be preserved.
	for _, want := range []string{"pce: poc3.illum.io", "pce_org: 3998508", "pce_poll_interval: 60", "plugin: PCEStdout"} {
		if !strings.Contains(got, want) {
			t.Errorf("migration dropped existing content %q", want)
		}
	}
}

func TestMigratePCEEventsConfig_Idempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(staleConfig), 0600)

	migratePCEEventsConfig(path, staleConfig, depsWithPort(443))
	first, _ := os.ReadFile(path)
	migratePCEEventsConfig(path, string(first), depsWithPort(443))
	second, _ := os.ReadFile(path)

	if string(first) != string(second) {
		t.Errorf("migration not idempotent:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Count(string(second), "pce_timeout:") != 1 {
		t.Errorf("pce_timeout duplicated on second run")
	}
}

func TestMigratePCEEventsConfig_UsesConfiguredPort(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	os.WriteFile(path, []byte(staleConfig), 0600)

	migratePCEEventsConfig(path, staleConfig, depsWithPort(8443))
	out, _ := os.ReadFile(path)
	if !strings.Contains(string(out), "pce_port: 8443") {
		t.Errorf("expected pce_port: 8443; got:\n%s", out)
	}
}
