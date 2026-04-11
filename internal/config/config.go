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
	DataDir           string `yaml:"dataDir"           mapstructure:"dataDir"`
	Network           string `yaml:"network"           mapstructure:"network"`
	EventPollInterval int    `yaml:"eventPollInterval" mapstructure:"eventPollInterval"`
	Registry          string `yaml:"registry"          mapstructure:"registry"`
	WebhookToken      string `yaml:"webhookToken"      mapstructure:"webhookToken"`
	DockerSocket      string `yaml:"dockerSocket"      mapstructure:"dockerSocket"`
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

logging:
  level: info
  format: text
`
	return os.WriteFile(path, []byte(content), 0600)
}
