package cli

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/config"
	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	var nonInteractive bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Initialize plugger — auto-detect Docker, configure PCE connection",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("Plugger Setup")
			fmt.Println("=============")
			fmt.Println()

			homeDir, _ := os.UserHomeDir()
			dataDir := filepath.Join(homeDir, ".plugger")

			// 1. Create data directory
			if err := os.MkdirAll(dataDir, 0700); err != nil {
				return fmt.Errorf("creating data directory: %w", err)
			}
			os.MkdirAll(filepath.Join(dataDir, "plugins"), 0700)
			os.MkdirAll(filepath.Join(dataDir, "cache"), 0700)
			fmt.Printf("✓ Data directory: %s\n", dataDir)

			// 2. Auto-detect Docker socket
			dockerSocket := detectDockerSocket()
			if dockerSocket != "" {
				fmt.Printf("✓ Docker socket: %s\n", dockerSocket)
			} else {
				fmt.Println("✗ Docker socket not found — set dockerSocket in config or DOCKER_HOST env var")
			}

			// 3. Check for .env file
			pceHost, pcePort, pceOrg, apiKey, apiSecret := "", "8443", "1", "", ""
			envFile := findEnvFile()
			if envFile != "" {
				fmt.Printf("✓ Found %s\n", envFile)
				vars := loadEnvFile(envFile)
				if v, ok := vars["PCE_HOST"]; ok {
					pceHost = v
				}
				if v, ok := vars["PCE_PORT"]; ok {
					pcePort = v
				}
				if v, ok := vars["PCE_ORG_ID"]; ok {
					pceOrg = v
				}
				if v, ok := vars["API_KEY"]; ok {
					apiKey = v
				}
				if v, ok := vars["PCE_API_KEY"]; ok {
					apiKey = v
				}
				if v, ok := vars["API_SECRET"]; ok {
					apiSecret = v
				}
				if v, ok := vars["PCE_API_SECRET"]; ok {
					apiSecret = v
				}
			}

			// 4. Check environment variables
			if v := os.Getenv("PCE_HOST"); v != "" {
				pceHost = v
			}
			if v := os.Getenv("PCE_API_KEY"); v != "" {
				apiKey = v
			}
			if v := os.Getenv("PCE_API_SECRET"); v != "" {
				apiSecret = v
			}

			// 5. Interactive prompts if needed
			reader := bufio.NewReader(os.Stdin)
			if !nonInteractive {
				if pceHost == "" {
					pceHost = prompt(reader, "PCE hostname", "")
				} else {
					fmt.Printf("  PCE host: %s\n", pceHost)
				}
				if pceHost != "" && apiKey == "" {
					apiKey = prompt(reader, "PCE API key", "")
				}
				if pceHost != "" && apiSecret == "" {
					apiSecret = prompt(reader, "PCE API secret", "")
				}
			}

			// 6. Test PCE connection
			if pceHost != "" && apiKey != "" {
				fmt.Printf("\nTesting PCE connection to %s:%s...\n", pceHost, pcePort)
				if testPCE(pceHost, pcePort) {
					fmt.Println("✓ PCE is reachable")
				} else {
					fmt.Println("⚠ PCE is not reachable (may need VPN or check hostname)")
				}
			}

			// 7. Write config
			cfgPath := filepath.Join(dataDir, "config.yaml")
			if _, err := os.Stat(cfgPath); os.IsNotExist(err) {
				writeConfig(cfgPath, dataDir, dockerSocket, pceHost, pcePort, pceOrg, apiKey, apiSecret)
				fmt.Printf("\n✓ Config written: %s\n", cfgPath)
			} else {
				fmt.Printf("\n✓ Config already exists: %s\n", cfgPath)
				// Update Docker socket if we found one and config doesn't have it
				if dockerSocket != "" {
					fmt.Printf("  Tip: add this to your config if Docker doesn't connect:\n")
					fmt.Printf("  dockerSocket: %s\n", dockerSocket)
				}
			}

			// 8. Generate self-signed TLS certificate
			if !config.TLSCertsExist(dataDir) {
				certPath, _, tlsErr := config.GenerateSelfSignedCert(dataDir)
				if tlsErr != nil {
					fmt.Printf("\n⚠ Failed to generate TLS certificate: %v\n", tlsErr)
				} else {
					fmt.Printf("\n✓ TLS certificate generated: %s\n", certPath)
					fmt.Println("  Dashboard will serve HTTPS by default (self-signed)")
					fmt.Println("  To use your own cert: set plugger.tls.certFile and keyFile in config.yaml")
				}
			} else {
				fmt.Printf("\n✓ TLS certificate exists: %s\n", config.TLSCertPath(dataDir))
			}

			// 9. Summary
			fmt.Println()
			fmt.Println("Next steps:")
			if pceHost == "" {
				fmt.Printf("  1. Edit %s with your PCE connection details\n", cfgPath)
				fmt.Println("  2. plugger search                    # Browse plugins")
				fmt.Println("  3. plugger install pce-health-monitor # Install a plugin")
				fmt.Println("  4. plugger run                        # Start everything")
			} else {
				fmt.Println("  plugger search                    # Browse available plugins")
				fmt.Println("  plugger install pce-health-monitor # Install your first plugin")
				fmt.Println("  plugger run                        # Start everything + dashboard")
			}
			fmt.Println()
			fmt.Println("Dashboard: http://localhost:8800")
			fmt.Println("Registry:  http://localhost:8800/registry")

			return nil
		},
	}

	cmd.Flags().BoolVar(&nonInteractive, "non-interactive", false, "skip interactive prompts")
	return cmd
}

// detectDockerSocket tries common Docker socket paths.
func detectDockerSocket() string {
	// Check DOCKER_HOST env first
	if dh := os.Getenv("DOCKER_HOST"); dh != "" {
		path := strings.TrimPrefix(dh, "unix://")
		if _, err := os.Stat(path); err == nil {
			return dh
		}
	}

	// Common socket paths
	paths := []string{
		"/var/run/docker.sock",
	}

	// macOS Docker Desktop paths
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		paths = append(paths,
			filepath.Join(homeDir, ".docker", "run", "docker.sock"),
			filepath.Join(homeDir, "Library", "Containers", "com.docker.docker", "Data", "docker.sock"),
		)
	}

	// Colima
	paths = append(paths,
		filepath.Join(homeDir, ".colima", "default", "docker.sock"),
		filepath.Join(homeDir, ".colima", "docker.sock"),
	)

	// Rancher Desktop
	paths = append(paths,
		filepath.Join(homeDir, ".rd", "docker.sock"),
	)

	// Podman
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		paths = append(paths, filepath.Join(xdg, "podman", "podman.sock"))
	}
	paths = append(paths, fmt.Sprintf("/run/user/%d/podman/podman.sock", os.Getuid()))

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			// Test if it's actually a socket
			conn, err := net.DialTimeout("unix", p, 2*time.Second)
			if err == nil {
				conn.Close()
				return "unix://" + p
			}
		}
	}

	return ""
}

// findEnvFile looks for .env files in common locations.
func findEnvFile() string {
	candidates := []string{
		".env",
		filepath.Join(".", ".env"),
	}
	homeDir, _ := os.UserHomeDir()
	if homeDir != "" {
		candidates = append(candidates,
			filepath.Join(homeDir, ".plugger", ".env"),
			filepath.Join(homeDir, ".env"),
		)
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// loadEnvFile reads key=value pairs from a file.
func loadEnvFile(path string) map[string]string {
	vars := make(map[string]string)
	f, err := os.Open(path)
	if err != nil {
		return vars
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			// Strip quotes
			val = strings.Trim(val, "\"'")
			vars[key] = val
		}
	}
	return vars
}

// prompt asks the user for input with an optional default.
func prompt(reader *bufio.Reader, label, defaultVal string) string {
	if defaultVal != "" {
		fmt.Printf("  %s [%s]: ", label, defaultVal)
	} else {
		fmt.Printf("  %s: ", label)
	}
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(input)
	if input == "" {
		return defaultVal
	}
	return input
}

// testPCE checks if the PCE is reachable.
func testPCE(host, port string) bool {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	resp, err := client.Get(fmt.Sprintf("https://%s:%s/api/v2/node_available", host, port))
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// writeConfig creates the config file with detected values.
func writeConfig(path, dataDir, dockerSocket, pceHost, pcePort, pceOrg, apiKey, apiSecret string) {
	tlsSkip := "false"
	if pceHost != "" {
		tlsSkip = "true"
	}

	dockerLine := "  # dockerSocket: unix:///var/run/docker.sock"
	if dockerSocket != "" {
		dockerLine = fmt.Sprintf("  dockerSocket: %s", dockerSocket)
	}

	content := fmt.Sprintf(`# Plugger configuration — generated by plugger init
pce:
  host: "%s"
  port: %s
  orgId: %s
  apiKey: "%s"
  apiSecret: "%s"
  tlsSkipVerify: %s

plugger:
  dataDir: %s
  network: plugger-net
  eventPollInterval: 30
%s
  # webhookToken: ""
  tls:
    enabled: true
    # certFile: ""    # Leave empty to use auto-generated self-signed cert
    # keyFile: ""     # Set both for BYO certificate from your CA

logging:
  level: info
  format: text
`, pceHost, pcePort, pceOrg, apiKey, apiSecret, tlsSkip, dataDir, dockerLine)

	os.WriteFile(path, []byte(content), 0600)
}
