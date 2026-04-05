package dashboard

import (
	"bufio"
	"fmt"
	"html"
	"net/http"
	"strings"

	"github.com/illumio/plugger/internal/container"
)

func (h *Handler) handleLogs(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")

	p, err := h.deps.Store.Get(name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	if p.ContainerID == "" {
		http.Error(w, "Plugin has no container", http.StatusBadRequest)
		return
	}

	follow := r.URL.Query().Get("follow") == "true"
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100"
	}

	reader, err := h.deps.Runtime.Logs(r.Context(), p.ContainerID, container.LogOpts{
		Follow: follow,
		Tail:   tail,
	})
	if err != nil {
		h.serverError(w, "getting logs", err)
		return
	}
	defer reader.Close()

	// SSE streaming mode
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming not supported", http.StatusInternalServerError)
		return
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()
		// Docker log lines have an 8-byte header for multiplexed streams.
		// Strip non-printable prefix bytes if present.
		line = stripDockerLogHeader(line)
		escaped := html.EscapeString(line)
		fmt.Fprintf(w, "data: <div>%s</div>\n\n", escaped)
		flusher.Flush()
	}
}

// stripDockerLogHeader removes the 8-byte Docker log multiplexing header
// that prefixes each line when the container is not using a TTY.
func stripDockerLogHeader(line string) string {
	if len(line) >= 8 {
		// Docker header: [stream_type, 0, 0, 0, size1, size2, size3, size4]
		// stream_type is 1 (stdout) or 2 (stderr)
		if (line[0] == 1 || line[0] == 2) && line[1] == 0 && line[2] == 0 && line[3] == 0 {
			return line[8:]
		}
	}
	// Also strip any remaining non-printable leading bytes
	return strings.TrimLeftFunc(line, func(r rune) bool {
		return r < 32 && r != '\t'
	})
}
