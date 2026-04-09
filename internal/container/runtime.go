package container

import (
	"context"
	"io"
	"time"
)

// Runtime abstracts container orchestration.
// Docker is the default implementation; Kubernetes can be added later.
type Runtime interface {
	// Pull fetches a container image.
	Pull(ctx context.Context, image string) error

	// Create creates a container (or pod) but does not start it.
	Create(ctx context.Context, opts CreateOpts) (id string, err error)

	// Start starts a previously created container.
	Start(ctx context.Context, id string) error

	// Stop stops a running container with a timeout for graceful shutdown.
	Stop(ctx context.Context, id string, timeout time.Duration) error

	// Remove removes a stopped container.
	Remove(ctx context.Context, id string) error

	// Inspect returns info about a container.
	Inspect(ctx context.Context, id string) (*ContainerInfo, error)

	// Logs returns a reader for container stdout/stderr.
	Logs(ctx context.Context, id string, opts LogOpts) (io.ReadCloser, error)

	// Wait blocks until the container exits and returns the result.
	Wait(ctx context.Context, id string) (<-chan WaitResult, error)

	// EnsureNetwork creates the network if it doesn't exist.
	EnsureNetwork(ctx context.Context, name string) error

	// ListManaged returns all containers managed by plugger.
	ListManaged(ctx context.Context) ([]ContainerInfo, error)

	// CopyFromImage extracts a file from an image by creating a temporary
	// container, copying the file out, and cleaning up. Returns the file
	// contents or an error if the file doesn't exist in the image.
	CopyFromImage(ctx context.Context, image string, srcPath string) ([]byte, error)
}

// CreateOpts are the options for creating a container.
type CreateOpts struct {
	Name      string
	Image     string
	Env       []string // KEY=VALUE pairs
	Network   string
	Labels    map[string]string
	Memory    int64  // bytes, 0 = no limit
	CPUs      string // e.g. "0.5"
	Ports     []PortMapping  // ports to expose on the host
	Volumes   []VolumeMount  // volumes to mount into the container
}

// PortMapping maps a container port to a host port.
type PortMapping struct {
	ContainerPort int    // port inside the container
	HostPort      int    // port on the host (0 = auto-assign)
	Protocol      string // tcp or udp
}

// VolumeMount maps a host path to a container path.
type VolumeMount struct {
	HostPath      string
	ContainerPath string
	ReadOnly      bool
}

// ContainerInfo holds status information about a container.
type ContainerInfo struct {
	ID      string
	Name    string
	Image   string
	Status  string // created, running, exited, etc.
	Running bool
	Labels  map[string]string
	Ports   map[int]int // containerPort -> hostPort (from actual bindings)
}

// LogOpts configures log retrieval.
type LogOpts struct {
	Follow bool
	Tail   string // number of lines, e.g. "100" or "all"
	Since  string // timestamp or relative (e.g. "1h")
}

// WaitResult is returned when a container exits.
type WaitResult struct {
	StatusCode int64
	Err        error
}

// Labels used by plugger to identify managed containers.
const (
	LabelManaged = "io.plugger.managed"
	LabelPlugin  = "io.plugger.plugin"
	LabelVersion = "io.plugger.version"
	LabelMode    = "io.plugger.mode"
)
