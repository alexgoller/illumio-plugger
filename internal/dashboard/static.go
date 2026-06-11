package dashboard

import (
	_ "embed"
	"net/http"
)

//go:embed logo.png
var logoPNG []byte

//go:embed logo.svg
var logoSVG []byte

func (h *Handler) handleLogo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logoPNG)
}

func (h *Handler) handleLogoSVG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Write(logoSVG)
}
