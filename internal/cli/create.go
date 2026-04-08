package cli

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

//go:embed all:templates/go
var goTemplate embed.FS

//go:embed all:templates/shell
var shellTemplate embed.FS

//go:embed all:templates/python
var pythonTemplate embed.FS

func newCreateCmd() *cobra.Command {
	var templateType string

	cmd := &cobra.Command{
		Use:   "create <plugin-name>",
		Short: "Scaffold a new plugin project from a template",
		Long: `Create a new plugin project directory with all the files needed to build
a plugger plugin. Templates available:
  go     — compiled Go binary with HTTP server and health endpoint
  shell  — lightweight shell script with curl + jq
  python — Python 3 with the Illumio SDK (illumio) pre-installed`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			// Validate name
			for _, c := range name {
				if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
					return fmt.Errorf("plugin name must be lowercase alphanumeric with hyphens/underscores, got %q", name)
				}
			}

			// Check if directory already exists
			if _, err := os.Stat(name); err == nil {
				return fmt.Errorf("directory %q already exists", name)
			}

			var templateFS embed.FS
			var templateRoot string
			switch templateType {
			case "go":
				templateFS = goTemplate
				templateRoot = "templates/go"
			case "shell":
				templateFS = shellTemplate
				templateRoot = "templates/shell"
			case "python":
				templateFS = pythonTemplate
				templateRoot = "templates/python"
			default:
				return fmt.Errorf("unknown template type %q (use 'go', 'shell', or 'python')", templateType)
			}

			// Walk and copy template files
			count := 0
			err := fs.WalkDir(templateFS, templateRoot, func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				// Compute relative path from template root
				relPath, _ := filepath.Rel(templateRoot, path)
				destPath := filepath.Join(name, relPath)

				// Strip .tmpl suffix for output filename
				destPath = strings.TrimSuffix(destPath, ".tmpl")

				if d.IsDir() {
					return os.MkdirAll(destPath, 0755)
				}

				data, err := templateFS.ReadFile(path)
				if err != nil {
					return fmt.Errorf("reading template file %s: %w", path, err)
				}

				// Replace template placeholders
				content := string(data)
				content = strings.ReplaceAll(content, "my-plugin", name)
				content = strings.ReplaceAll(content, "my-shell-plugin", name)
				content = strings.ReplaceAll(content, "My Plugin", titleCase(name))
				content = strings.ReplaceAll(content, "My Shell Plugin", titleCase(name))
				content = strings.ReplaceAll(content, "my_plugin", strings.ReplaceAll(name, "-", "_"))
				content = strings.ReplaceAll(content, "github.com/your-org/my-plugin", fmt.Sprintf("github.com/your-org/%s", name))

				if err := os.WriteFile(destPath, []byte(content), 0644); err != nil {
					return fmt.Errorf("writing %s: %w", destPath, err)
				}

				// Make scripts executable
				if strings.HasSuffix(destPath, ".sh") || strings.HasSuffix(destPath, ".py") {
					os.Chmod(destPath, 0755)
				}

				count++
				return nil
			})
			if err != nil {
				return fmt.Errorf("scaffolding plugin: %w", err)
			}

			fmt.Printf("Created plugin %q (%s template, %d files)\n\n", name, templateType, count)
			fmt.Printf("Next steps:\n")
			fmt.Printf("  cd %s\n", name)
			switch templateType {
			case "go":
				fmt.Printf("  # Edit main.go with your plugin logic\n")
			case "python":
				fmt.Printf("  # Edit main.py with your plugin logic (illumio SDK pre-installed)\n")
			default:
				fmt.Printf("  # Edit entrypoint.sh with your plugin logic\n")
			}
			fmt.Printf("  docker build -t %s:latest .\n", name)
			fmt.Printf("  plugger install plugin.yaml\n")
			fmt.Printf("  plugger start %s\n", name)
			return nil
		},
	}

	cmd.Flags().StringVarP(&templateType, "template", "t", "go", "template type: go, shell, or python")
	return cmd
}

func titleCase(s string) string {
	words := strings.FieldsFunc(s, func(c rune) bool { return c == '-' || c == '_' })
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}
