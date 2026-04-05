package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/container"
	"github.com/illumio/plugger/internal/logging"
	"github.com/illumio/plugger/internal/plugin"
	"github.com/spf13/cobra"
)

// Version is set at build time via ldflags.
var Version = "dev"

// App holds shared dependencies for all CLI commands.
type App struct {
	Config  *config.Config
	Store   *plugin.Store
	Runtime container.Runtime
	Logger  *slog.Logger
}

var (
	cfgFile string
	app     *App
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "plugger",
		Short: "Illumio plugin framework — manage PCE plugins as containers",
		Long: `Plugger manages Illumio PCE plugins running as Docker containers (or Kubernetes pods).
It handles the full plugin lifecycle: install, start, stop, logging, credential injection,
health checks, and scheduling (daemon, cron, event-driven).`,
		SilenceUsage: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Skip init for the init command itself and version
			if cmd.Name() == "init" || cmd.Name() == "version" || cmd.Name() == "create" {
				return nil
			}
			return initApp()
		},
	}

	root.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default: ~/.plugger/config.yaml)")

	root.AddCommand(
		newInitCmd(),
		newCreateCmd(),
		newInstallCmd(),
		newUninstallCmd(),
		newStartCmd(),
		newStopCmd(),
		newRestartCmd(),
		newListCmd(),
		newStatusCmd(),
		newLogsCmd(),
		newVersionCmd(),
	)

	return root
}

func initApp() error {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	logger, err := logging.Setup(cfg.Logging.Level, cfg.Logging.Format, cfg.Logging.File)
	if err != nil {
		return fmt.Errorf("setting up logging: %w", err)
	}

	rt, err := container.NewDockerRuntime()
	if err != nil {
		return fmt.Errorf("connecting to container runtime: %w", err)
	}

	app = &App{
		Config:  cfg,
		Store:   plugin.NewStore(cfg.Plugger.DataDir),
		Runtime: rt,
		Logger:  logger,
	}

	return nil
}

// Execute runs the root command.
func Execute() {
	if err := newRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
