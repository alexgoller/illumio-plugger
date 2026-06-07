package cli

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/illumio/plugger/internal/config"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

func newAuthCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage API keys for dashboard and plugin authentication",
	}

	cmd.AddCommand(
		newAuthCreateKeyCmd(),
		newAuthListKeysCmd(),
		newAuthRevokeKeyCmd(),
		newAuthTestKeyCmd(),
	)

	return cmd
}

func newAuthCreateKeyCmd() *cobra.Command {
	var (
		name        string
		plugins     string
		dashboard   bool
		description string
	)

	cmd := &cobra.Command{
		Use:   "create-key",
		Short: "Create a new API key",
		Long: `Create a new API key with per-plugin permissions.

Examples:
  plugger auth create-key --name "SOC Team" --plugins workload-isolator:write,ai-security-report:read
  plugger auth create-key --name "Viewer" --plugins "*:read" --dashboard`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				return fmt.Errorf("--name is required")
			}

			// Generate key
			b := make([]byte, 24)
			if _, err := rand.Read(b); err != nil {
				return fmt.Errorf("generating key: %w", err)
			}
			slug := strings.ToLower(strings.ReplaceAll(name, " ", "-"))
			if len(slug) > 12 {
				slug = slug[:12]
			}
			key := fmt.Sprintf("pk_%s_%s", slug, hex.EncodeToString(b))

			// Parse plugins
			pluginMap := make(map[string]string)
			defaultAccess := ""
			if plugins != "" {
				for _, p := range strings.Split(plugins, ",") {
					parts := strings.SplitN(strings.TrimSpace(p), ":", 2)
					if len(parts) == 2 {
						if parts[0] == "*" {
							defaultAccess = parts[1]
						} else {
							pluginMap[parts[0]] = parts[1]
						}
					} else if len(parts) == 1 {
						pluginMap[parts[0]] = "read"
					}
				}
			}

			keyConfig := config.APIKeyConfig{
				Key:         key,
				Name:        name,
				Description: description,
				Plugins:     pluginMap,
				Access:      defaultAccess,
				Dashboard:   dashboard,
			}

			fmt.Printf("API Key created:\n\n")
			fmt.Printf("  Key:         %s\n", key)
			fmt.Printf("  Name:        %s\n", name)
			if description != "" {
				fmt.Printf("  Description: %s\n", description)
			}
			fmt.Printf("  Dashboard:   %v\n", dashboard)
			if len(pluginMap) > 0 {
				fmt.Printf("  Plugins:\n")
				for p, a := range pluginMap {
					fmt.Printf("    %s: %s\n", p, a)
				}
			}
			if defaultAccess != "" {
				fmt.Printf("  Default access: %s (all plugins)\n", defaultAccess)
			}

			fmt.Printf("\nAdd this to your config.yaml under plugger.auth.keys:\n\n")

			yamlBytes, _ := yaml.Marshal([]config.APIKeyConfig{keyConfig})
			fmt.Printf("    %s\n", strings.ReplaceAll(string(yamlBytes), "\n", "\n    "))

			fmt.Printf("\n⚠️  Save this key now — it cannot be retrieved later.\n")
			return nil
		},
	}

	cmd.Flags().StringVar(&name, "name", "", "key name (required)")
	cmd.Flags().StringVar(&plugins, "plugins", "", "plugin permissions: name:access,... (e.g., workload-isolator:write,*:read)")
	cmd.Flags().BoolVar(&dashboard, "dashboard", true, "allow dashboard access")
	cmd.Flags().StringVar(&description, "description", "", "key description")
	return cmd
}

func newAuthListKeysCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list-keys",
		Short: "List configured API keys (masked)",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := app.Config
			if !cfg.Plugger.Auth.Enabled {
				fmt.Println("Auth is disabled (plugger.auth.enabled = false)")
				return nil
			}

			if cfg.Plugger.Auth.MasterKey != "" {
				masked := cfg.Plugger.Auth.MasterKey[:12] + "..."
				fmt.Printf("Master key: %s\n\n", masked)
			}

			if len(cfg.Plugger.Auth.Keys) == 0 {
				fmt.Println("No API keys configured")
				return nil
			}

			fmt.Printf("%-20s %-15s %-40s %s\n", "NAME", "KEY PREFIX", "PLUGINS", "DASHBOARD")
			fmt.Printf("%-20s %-15s %-40s %s\n", "----", "----------", "-------", "---------")
			for _, k := range cfg.Plugger.Auth.Keys {
				prefix := k.Key
				if len(prefix) > 15 {
					prefix = prefix[:15] + "..."
				}

				var pluginDesc string
				if k.Access != "" {
					pluginDesc = fmt.Sprintf("*:%s", k.Access)
				} else {
					parts := []string{}
					for p, a := range k.Plugins {
						parts = append(parts, fmt.Sprintf("%s:%s", p, a))
					}
					pluginDesc = strings.Join(parts, ", ")
				}
				if len(pluginDesc) > 40 {
					pluginDesc = pluginDesc[:37] + "..."
				}

				dash := "no"
				if k.Dashboard {
					dash = "yes"
				}
				fmt.Printf("%-20s %-15s %-40s %s\n", k.Name, prefix, pluginDesc, dash)
			}
			return nil
		},
	}
}

func newAuthRevokeKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "revoke-key <key-prefix>",
		Short: "Show instructions for revoking an API key",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			prefix := args[0]
			fmt.Printf("To revoke a key, remove it from your config.yaml:\n\n")
			fmt.Printf("  1. Edit ~/.plugger/config.yaml\n")
			fmt.Printf("  2. Find the key starting with: %s\n", prefix)
			fmt.Printf("  3. Remove the entire key entry from plugger.auth.keys\n")
			fmt.Printf("  4. Restart plugger: plugger run\n\n")
			fmt.Printf("The key will be immediately invalid after restart.\n")
			return nil
		},
	}
}

func newAuthTestKeyCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test-key <api-key>",
		Short: "Test if an API key is valid and show its permissions",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			testKey := args[0]
			cfg := app.Config

			if !cfg.Plugger.Auth.Enabled {
				fmt.Println("Auth is disabled — all keys are accepted")
				return nil
			}

			// Check master key
			if testKey == cfg.Plugger.Auth.MasterKey {
				fmt.Println("✓ Valid: Master key (full access to everything)")
				return nil
			}

			// Check configured keys
			for _, k := range cfg.Plugger.Auth.Keys {
				if testKey == k.Key {
					fmt.Printf("✓ Valid: %s\n", k.Name)
					if k.Description != "" {
						fmt.Printf("  Description: %s\n", k.Description)
					}
					fmt.Printf("  Dashboard: %v\n", k.Dashboard)
					if k.Access != "" {
						fmt.Printf("  All plugins: %s\n", k.Access)
					}
					for p, a := range k.Plugins {
						fmt.Printf("  %s: %s\n", p, a)
					}
					return nil
				}
			}

			fmt.Println("✗ Invalid: key not found")
			os.Exit(1)
			return nil
		},
	}
}
