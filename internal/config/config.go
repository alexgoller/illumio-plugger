package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config struct {
	PCE     PCEConfig     `yaml:"pce"     mapstructure:"pce"`
	Plugger PluggerConfig `yaml:"plugger" mapstructure:"plugger"`
	Logging LoggingConfig `yaml:"logging" mapstructure:"logging"`
}

type PCEConfig struct {
	Host          string `yaml:"host"          mapstructure:"host"`
	Port          int    `yaml:"port"          mapstructure:"port"`
	OrgID         int    `yaml:"orgId"         mapstructure:"orgId"`
	APIKey        string `yaml:"apiKey"        mapstructure:"apiKey"`
	APISecret     string `yaml:"apiSecret"     mapstructure:"apiSecret"`
	TLSSkipVerify bool   `yaml:"tlsSkipVerify" mapstructure:"tlsSkipVerify"`
}

type PluggerConfig struct {
	DataDir           string         `yaml:"dataDir"           mapstructure:"dataDir"`
	Network           string         `yaml:"network"           mapstructure:"network"`
	EventPollInterval int            `yaml:"eventPollInterval" mapstructure:"eventPollInterval"`
	Registry          string         `yaml:"registry"          mapstructure:"registry"`
	WebhookToken      string         `yaml:"webhookToken"      mapstructure:"webhookToken"`
	DockerSocket      string         `yaml:"dockerSocket"      mapstructure:"dockerSocket"`
	TLS               TLSConfig      `yaml:"tls"               mapstructure:"tls"`
	Auth              AuthConfig     `yaml:"auth"              mapstructure:"auth"`
	Outputs           []OutputConfig `yaml:"outputs"           mapstructure:"outputs"`
}

// OutputConfig defines a single output channel for the reporting framework.
type OutputConfig struct {
	Name    string       `yaml:"name"    mapstructure:"name"`
	Type    string       `yaml:"type"    mapstructure:"type"` // slack, email, webhook
	Enabled *bool        `yaml:"enabled" mapstructure:"enabled"`
	DryRun  bool         `yaml:"dryRun"  mapstructure:"dryRun"`
	Filter  OutputFilter `yaml:"filter"  mapstructure:"filter"`

	// Slack
	Webhook string `yaml:"webhook" mapstructure:"webhook"`

	// Email
	SMTPHost        string   `yaml:"smtpHost"        mapstructure:"smtpHost"`
	SMTPPort        int      `yaml:"smtpPort"        mapstructure:"smtpPort"`
	SMTPUser        string   `yaml:"smtpUser"        mapstructure:"smtpUser"`
	SMTPPasswordEnv string   `yaml:"smtpPasswordEnv" mapstructure:"smtpPasswordEnv"`
	From            string   `yaml:"from"            mapstructure:"from"`
	To              []string `yaml:"to"              mapstructure:"to"`
	Schedule        string   `yaml:"schedule"        mapstructure:"schedule"`
	Aggregate       bool     `yaml:"aggregate"       mapstructure:"aggregate"`

	// Webhook
	URL     string            `yaml:"url"     mapstructure:"url"`
	Method  string            `yaml:"method"  mapstructure:"method"`
	Headers map[string]string `yaml:"headers" mapstructure:"headers"`
}

// OutputFilter determines which reports are routed to an output.
type OutputFilter struct {
	Severity []string `yaml:"severity" mapstructure:"severity"`
	Plugins  []string `yaml:"plugins"  mapstructure:"plugins"`
	Tags     []string `yaml:"tags"     mapstructure:"tags"`
}

// IsEnabled returns true if the output is enabled (default: true).
func (o *OutputConfig) IsEnabled() bool {
	if o.Enabled == nil {
		return true
	}
	return *o.Enabled
}

type AuthConfig struct {
	Enabled   bool           `yaml:"enabled"   mapstructure:"enabled"`
	MasterKey string         `yaml:"masterKey" mapstructure:"masterKey"`
	Dashboard DashboardAuth  `yaml:"dashboard" mapstructure:"dashboard"`
	Keys      []APIKeyConfig `yaml:"keys"      mapstructure:"keys"`
}

type DashboardAuth struct {
	Method     string `yaml:"method"     mapstructure:"method"`     // "key" or "none"
	SessionTTL int    `yaml:"sessionTTL" mapstructure:"sessionTTL"` // seconds
}

type APIKeyConfig struct {
	Key         string            `yaml:"key"         mapstructure:"key"`
	Name        string            `yaml:"name"        mapstructure:"name"`
	Description string            `yaml:"description" mapstructure:"description"`
	Plugins     map[string]string `yaml:"plugins"     mapstructure:"plugins"` // plugin -> "read"|"write"
	Access      string            `yaml:"access"      mapstructure:"access"`  // default access for wildcard
	Dashboard   bool              `yaml:"dashboard"   mapstructure:"dashboard"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"  mapstructure:"enabled"`
	CertFile string `yaml:"certFile" mapstructure:"certFile"`
	KeyFile  string `yaml:"keyFile"  mapstructure:"keyFile"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"  mapstructure:"level"`
	Format string `yaml:"format" mapstructure:"format"`
	File   string `yaml:"file"   mapstructure:"file"`
}

// DefaultDataDir returns ~/.plugger.
func DefaultDataDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".plugger")
}

// DefaultConfig returns a config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		PCE: PCEConfig{
			Port: 8443,
			OrgID: 1,
		},
		Plugger: PluggerConfig{
			DataDir:           DefaultDataDir(),
			Network:           "plugger-net",
			EventPollInterval: 30,
			Auth: AuthConfig{
				Enabled: false,
				Dashboard: DashboardAuth{
					Method:     "key",
					SessionTTL: 86400,
				},
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
	}
}

// Load reads config from the given path or the default location.
func Load(cfgFile string) (*Config, error) {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
		viper.AddConfigPath(DefaultDataDir())
	}

	// Set defaults
	viper.SetDefault("pce.port", 8443)
	viper.SetDefault("pce.orgId", 1)
	viper.SetDefault("plugger.dataDir", DefaultDataDir())
	viper.SetDefault("plugger.network", "plugger-net")
	viper.SetDefault("plugger.eventPollInterval", 30)
	viper.SetDefault("plugger.auth.enabled", false)
	viper.SetDefault("plugger.auth.dashboard.method", "key")
	viper.SetDefault("plugger.auth.dashboard.sessionTTL", 86400)
	viper.SetDefault("logging.level", "info")
	viper.SetDefault("logging.format", "text")

	viper.SetEnvPrefix("PLUGGER")
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("reading config: %w", err)
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	return &cfg, nil
}

// WriteDefault writes a default config file to the given path.
func WriteDefault(path string) error {
	content := `# Plugger configuration
pce:
  host: ""
  port: 8443
  orgId: 1
  apiKey: ""
  apiSecret: ""
  tlsSkipVerify: false

plugger:
  dataDir: ` + DefaultDataDir() + `
  network: plugger-net
  eventPollInterval: 30
  # dockerSocket: unix:///var/run/docker.sock
  # webhookToken: ""
  tls:
    enabled: true
    # certFile: ""    # Leave empty for auto-generated self-signed cert
    # keyFile: ""     # Set both for BYO certificate
  auth:
    enabled: false
    # masterKey: ""   # Master key that grants full access (set via PLUGGER_PLUGGER_AUTH_MASTERKEY env)
    dashboard:
      method: key     # "key" or "none"
      sessionTTL: 86400  # session lifetime in seconds (24h)
    # keys:
    #   - key: "pk_your_api_key_here"
    #     name: "my-automation"
    #     description: "CI/CD pipeline key"
    #     dashboard: false
    #     access: "read"   # default access level for unlisted plugins
    #     plugins:
    #       my-plugin: "write"

logging:
  level: info
  format: text
`
	return os.WriteFile(path, []byte(content), 0600)
}
