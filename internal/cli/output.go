package cli

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/illumio/plugger/internal/config"
	"github.com/illumio/plugger/internal/reports"
	"github.com/spf13/cobra"
)

func newOutputCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "output",
		Short: "Manage notification output channels (Slack, email, webhook)",
		Long:  "Add, list, remove, and test output channels for the reporting framework.",
	}

	cmd.AddCommand(
		newOutputAddCmd(),
		newOutputListCmd(),
		newOutputRemoveCmd(),
		newOutputTestCmd(),
	)

	return cmd
}

func newOutputAddCmd() *cobra.Command {
	var (
		outputType string
		webhook    string
		url        string
		method     string
		headers    []string
		smtpHost   string
		smtpPort   int
		smtpUser   string
		smtpPassEnv string
		from       string
		to         []string
		schedule   string
		aggregate  bool
		severity   []string
		plugins    []string
		tags       []string
		dryRun     bool
	)

	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Add a notification output channel",
		Long: `Add a new output channel for report delivery.

Examples:
  plugger output add my-slack --type slack --webhook https://hooks.slack.com/services/...
  plugger output add alerts --type slack --webhook https://hooks.slack.com/... --severity warning,critical
  plugger output add my-webhook --type webhook --url https://api.example.com/alerts --header "Authorization=Bearer token"
  plugger output add team-email --type email --smtp-host smtp.corp.com --to security@corp.com --schedule "0 8 * * 1" --aggregate`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			if outputType == "" {
				return fmt.Errorf("--type is required (slack, email, webhook)")
			}

			o := config.OutputConfig{
				Name:   name,
				Type:   outputType,
				DryRun: dryRun,
				Filter: config.OutputFilter{
					Severity: severity,
					Plugins:  plugins,
					Tags:     tags,
				},
			}

			switch outputType {
			case "slack":
				if webhook == "" {
					return fmt.Errorf("--webhook is required for slack outputs")
				}
				o.Webhook = webhook
			case "email":
				if smtpHost == "" {
					return fmt.Errorf("--smtp-host is required for email outputs")
				}
				if len(to) == 0 {
					return fmt.Errorf("--to is required for email outputs")
				}
				o.SMTPHost = smtpHost
				o.SMTPPort = smtpPort
				o.SMTPUser = smtpUser
				o.SMTPPasswordEnv = smtpPassEnv
				o.From = from
				o.To = to
				o.Schedule = schedule
				o.Aggregate = aggregate
			case "webhook":
				if url == "" {
					return fmt.Errorf("--url is required for webhook outputs")
				}
				o.URL = url
				o.Method = method
				headerMap := make(map[string]string)
				for _, h := range headers {
					parts := strings.SplitN(h, "=", 2)
					if len(parts) == 2 {
						headerMap[parts[0]] = parts[1]
					}
				}
				if len(headerMap) > 0 {
					o.Headers = headerMap
				}
			default:
				return fmt.Errorf("unknown output type: %s (use slack, email, or webhook)", outputType)
			}

			store := reports.NewOutputStore(app.Config.Plugger.DataDir)
			if err := store.Add(o); err != nil {
				return err
			}

			fmt.Printf("Added output %q (type=%s)\n", name, outputType)
			if dryRun {
				fmt.Println("  Mode: dry-run (will log but not send)")
			}
			if len(severity) > 0 {
				fmt.Printf("  Filter severity: %s\n", strings.Join(severity, ", "))
			}
			fmt.Println("\nRestart plugger to activate: plugger reload")
			return nil
		},
	}

	cmd.Flags().StringVar(&outputType, "type", "", "output type: slack, email, webhook")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "log reports without sending")

	// Slack
	cmd.Flags().StringVar(&webhook, "webhook", "", "Slack webhook URL")

	// Webhook
	cmd.Flags().StringVar(&url, "url", "", "webhook URL")
	cmd.Flags().StringVar(&method, "method", "POST", "HTTP method for webhook")
	cmd.Flags().StringArrayVar(&headers, "header", nil, "webhook headers (Key=Value)")

	// Email
	cmd.Flags().StringVar(&smtpHost, "smtp-host", "", "SMTP server hostname")
	cmd.Flags().IntVar(&smtpPort, "smtp-port", 587, "SMTP server port")
	cmd.Flags().StringVar(&smtpUser, "smtp-user", "", "SMTP username")
	cmd.Flags().StringVar(&smtpPassEnv, "smtp-password-env", "", "env var name containing SMTP password")
	cmd.Flags().StringVar(&from, "from", "", "email from address")
	cmd.Flags().StringSliceVar(&to, "to", nil, "email recipients")
	cmd.Flags().StringVar(&schedule, "schedule", "", "cron schedule for digest delivery")
	cmd.Flags().BoolVar(&aggregate, "aggregate", false, "aggregate reports into digest")

	// Filters
	cmd.Flags().StringSliceVar(&severity, "severity", nil, "filter by severity (info,warning,critical)")
	cmd.Flags().StringSliceVar(&plugins, "plugins", nil, "filter by plugin names")
	cmd.Flags().StringSliceVar(&tags, "tags", nil, "filter by report tags")

	return cmd
}

func newOutputListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured output channels",
		RunE: func(cmd *cobra.Command, args []string) error {
			store := reports.NewOutputStore(app.Config.Plugger.DataDir)
			stored, err := store.List()
			if err != nil {
				return err
			}

			all := reports.MergeWithConfig(app.Config.Plugger.Outputs, stored)

			if len(all) == 0 {
				fmt.Println("No output channels configured.")
				fmt.Println("Add one with: plugger output add <name> --type slack --webhook <url>")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tTYPE\tDRY-RUN\tFILTER\tSOURCE")

			configNames := make(map[string]bool)
			for _, o := range app.Config.Plugger.Outputs {
				configNames[o.Name] = true
			}

			for _, o := range all {
				filter := ""
				if len(o.Filter.Severity) > 0 {
					filter = "severity=" + strings.Join(o.Filter.Severity, ",")
				}
				if len(o.Filter.Plugins) > 0 {
					if filter != "" {
						filter += " "
					}
					filter += "plugins=" + strings.Join(o.Filter.Plugins, ",")
				}
				if filter == "" {
					filter = "all"
				}

				source := "store"
				if configNames[o.Name] {
					source = "config"
				}

				dryStr := "no"
				if o.DryRun {
					dryStr = "yes"
				}

				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", o.Name, o.Type, dryStr, filter, source)
			}
			w.Flush()
			return nil
		},
	}
}

func newOutputRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Remove an output channel",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			// Check if it's a config-file output
			for _, o := range app.Config.Plugger.Outputs {
				if o.Name == name {
					return fmt.Errorf("output %q is defined in config.yaml — remove it from the config file directly", name)
				}
			}

			store := reports.NewOutputStore(app.Config.Plugger.DataDir)
			if err := store.Remove(name); err != nil {
				return err
			}

			fmt.Printf("Removed output %q\n", name)
			fmt.Println("Restart plugger to apply: plugger reload")
			return nil
		},
	}
}

func newOutputTestCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "test <name>",
		Short: "Send a test message to an output channel",
		Long:  "Sends a test report to the named output via the running plugger dashboard API.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			addr := "localhost:8800"
			url := fmt.Sprintf("http://%s/api/reports/test/%s", addr, name)

			status, errMsg, err := sendTestRequest(url)
			if err != nil {
				return fmt.Errorf("failed to reach plugger at %s: %w", addr, err)
			}

			if status == "delivered" {
				fmt.Printf("Test message sent to %q\n", name)
			} else {
				fmt.Printf("Test failed for %q: %s\n", name, errMsg)
			}
			return nil
		},
	}
}

func sendTestRequest(url string) (status string, errMsg string, err error) {
	resp, err := http.Post(url, "application/json", nil)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	var result map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", "", fmt.Errorf("invalid response: %w", err)
	}
	return result["status"], result["error"], nil
}
