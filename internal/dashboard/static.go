package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed logo.png
var logoPNG []byte

func (h *Handler) handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logoPNG)
}
