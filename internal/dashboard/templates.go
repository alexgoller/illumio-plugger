package dashboard

import (
	"embed"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/illumio/plugger/internal/plugin"
)

//go:embed templates/*.html
var templateFS embed.FS

var funcMap = template.FuncMap{
	"timeAgo": func(t *time.Time) string {
		if t == nil {
			return "—"
		}
		d := time.Since(*t)
		switch {
		case d < time.Minute:
			return "just now"
		case d < time.Hour:
			m := int(d.Minutes())
			return fmt.Sprintf("%dm ago", m)
		case d < 24*time.Hour:
			h := int(d.Hours())
			return fmt.Sprintf("%dh ago", h)
		default:
			days := int(d.Hours() / 24)
			return fmt.Sprintf("%dd ago", days)
		}
	},
	"contains": func(s, substr string) bool {
		return strings.Contains(s, substr)
	},
	"deref": func(p *int) int {
		if p == nil {
			return -1
		}
		return *p
	},
	"configData": func(p *plugin.Plugin) map[string]any {
		return map[string]any{
			"Plugin":  p,
			"Fields":  BuildConfigFields(p),
			"Message": "",
		}
	},
	"stateColor": func(s plugin.State) string {
		switch s {
		case plugin.StateRunning:
			return "green"
		case plugin.StateErrored:
			return "red"
		case plugin.StateStopped:
			return "gray"
		case plugin.StateStarting:
			return "yellow"
		default:
			return "blue"
		}
	},
}

func parseTemplates() *template.Template {
	return template.Must(
		template.New("").Funcs(funcMap).ParseFS(templateFS, "templates/*.html"),
	)
}
