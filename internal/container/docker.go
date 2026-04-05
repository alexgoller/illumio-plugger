package container

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"time"

	containertypes "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// DockerRuntime implements Runtime using the Docker Engine API.
type DockerRuntime struct {
	cli *client.Client
}

// NewDockerRuntime creates a new Docker runtime using the default Docker socket.
func NewDockerRuntime() (*DockerRuntime, error) {
	cli, err := client.New(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("connecting to docker: %w", err)
	}
	return &DockerRuntime{cli: cli}, nil
}

func (d *DockerRuntime) Pull(ctx context.Context, img string) error {
	resp, err := d.cli.ImagePull(ctx, img, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image %s: %w", img, err)
	}
	defer resp.Close()
	// Consume the reader to complete the pull
	_, err = io.Copy(io.Discard, resp)
	return err
}

func (d *DockerRuntime) Create(ctx context.Context, opts CreateOpts) (string, error) {
	containerCfg := &containertypes.Config{
		Image:  opts.Image,
		Env:    opts.Env,
		Labels: opts.Labels,
	}

	hostCfg := &containertypes.HostConfig{}
	if opts.Memory > 0 {
		hostCfg.Resources.Memory = opts.Memory
	}
	if opts.CPUs != "" {
		cpus, err := strconv.ParseFloat(opts.CPUs, 64)
		if err == nil {
			hostCfg.Resources.NanoCPUs = int64(cpus * 1e9)
		}
	}

	networkCfg := &network.NetworkingConfig{}
	if opts.Network != "" {
		networkCfg.EndpointsConfig = map[string]*network.EndpointSettings{
			opts.Network: {},
		}
	}

	resp, err := d.cli.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:           containerCfg,
		HostConfig:       hostCfg,
		NetworkingConfig: networkCfg,
		Name:             opts.Name,
	})
	if err != nil {
		return "", fmt.Errorf("creating container %s: %w", opts.Name, err)
	}
	return resp.ID, nil
}

func (d *DockerRuntime) Start(ctx context.Context, id string) error {
	_, err := d.cli.ContainerStart(ctx, id, client.ContainerStartOptions{})
	return err
}

func (d *DockerRuntime) Stop(ctx context.Context, id string, timeout time.Duration) error {
	timeoutSec := int(timeout.Seconds())
	_, err := d.cli.ContainerStop(ctx, id, client.ContainerStopOptions{Timeout: &timeoutSec})
	return err
}

func (d *DockerRuntime) Remove(ctx context.Context, id string) error {
	_, err := d.cli.ContainerRemove(ctx, id, client.ContainerRemoveOptions{Force: true})
	return err
}

func (d *DockerRuntime) Inspect(ctx context.Context, id string) (*ContainerInfo, error) {
	resp, err := d.cli.ContainerInspect(ctx, id, client.ContainerInspectOptions{})
	if err != nil {
		return nil, fmt.Errorf("inspecting container %s: %w", id, err)
	}

	c := resp.Container
	name := c.Name
	if len(name) > 0 && name[0] == '/' {
		name = name[1:]
	}

	return &ContainerInfo{
		ID:      c.ID,
		Name:    name,
		Image:   c.Config.Image,
		Status:  string(c.State.Status),
		Running: c.State.Running,
		Labels:  c.Config.Labels,
	}, nil
}

func (d *DockerRuntime) Logs(ctx context.Context, id string, opts LogOpts) (io.ReadCloser, error) {
	return d.cli.ContainerLogs(ctx, id, client.ContainerLogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Follow:     opts.Follow,
		Tail:       opts.Tail,
		Since:      opts.Since,
	})
}

func (d *DockerRuntime) Wait(ctx context.Context, id string) (<-chan WaitResult, error) {
	waitResult := d.cli.ContainerWait(ctx, id, client.ContainerWaitOptions{
		Condition: containertypes.WaitConditionNotRunning,
	})
	resultCh := make(chan WaitResult, 1)

	go func() {
		select {
		case body := <-waitResult.Result:
			resultCh <- WaitResult{StatusCode: body.StatusCode}
		case err := <-waitResult.Error:
			resultCh <- WaitResult{Err: err}
		}
	}()

	return resultCh, nil
}

func (d *DockerRuntime) EnsureNetwork(ctx context.Context, name string) error {
	networks, err := d.cli.NetworkList(ctx, client.NetworkListOptions{
		Filters: client.Filters{}.Add("name", name),
	})
	if err != nil {
		return fmt.Errorf("listing networks: %w", err)
	}
	for _, n := range networks.Items {
		if n.Name == name {
			return nil
		}
	}

	_, err = d.cli.NetworkCreate(ctx, name, client.NetworkCreateOptions{
		Driver: "bridge",
	})
	if err != nil {
		return fmt.Errorf("creating network %s: %w", name, err)
	}
	return nil
}

func (d *DockerRuntime) ListManaged(ctx context.Context) ([]ContainerInfo, error) {
	resp, err := d.cli.ContainerList(ctx, client.ContainerListOptions{
		All:     true,
		Filters: client.Filters{}.Add("label", LabelManaged+"=true"),
	})
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	result := make([]ContainerInfo, 0, len(resp.Items))
	for _, c := range resp.Items {
		name := ""
		if len(c.Names) > 0 {
			name = c.Names[0]
			if len(name) > 0 && name[0] == '/' {
				name = name[1:]
			}
		}
		result = append(result, ContainerInfo{
			ID:      c.ID,
			Name:    name,
			Image:   c.Image,
			Status:  string(c.State),
			Running: c.State == "running",
			Labels:  c.Labels,
		})
	}
	return result, nil
}
