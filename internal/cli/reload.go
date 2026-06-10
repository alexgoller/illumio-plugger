package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
)

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reload",
		Short: "Reload config and restart all plugins (sends SIGHUP to running plugger)",
		Long: `Reload the plugger configuration without stopping the orchestrator.

This sends SIGHUP to the running plugger process, which:
  1. Re-reads ~/.plugger/config.yaml
  2. Stops all running plugin containers
  3. Restarts them with the new config (new PCE credentials, env vars, etc.)

The dashboard stays up throughout. Use this after changing PCE credentials,
plugin settings, or auth configuration.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			dataDir := app.Config.Plugger.DataDir
			pidFile := filepath.Join(dataDir, "plugger.pid")

			data, err := os.ReadFile(pidFile)
			if err != nil {
				return fmt.Errorf("plugger is not running (no PID file at %s)", pidFile)
			}

			pidStr := strings.TrimSpace(string(data))
			pid, err := strconv.Atoi(pidStr)
			if err != nil {
				return fmt.Errorf("invalid PID file: %s", pidStr)
			}

			proc, err := os.FindProcess(pid)
			if err != nil {
				return fmt.Errorf("process %d not found: %w", pid, err)
			}

			if err := proc.Signal(syscall.SIGHUP); err != nil {
				return fmt.Errorf("failed to send SIGHUP to process %d: %w", pid, err)
			}

			fmt.Printf("Sent reload signal to plugger (PID %d)\n", pid)
			fmt.Println("Config will be re-read and all plugins restarted.")
			return nil
		},
	}
}
