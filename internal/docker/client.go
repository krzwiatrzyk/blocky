// Package docker wraps the Docker SDK with a small interface tailored to blocky.
//
// Only three operations are needed:
//   - List currently running containers (used at startup to seed the reconciler)
//   - Inspect a single container by ID (used to read labels + PID for netns lookup)
//   - Stream container start/die/destroy/update events
package docker

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
)

// Client is the blocky-facing API surface. Tests implement this with fakes.
type Client interface {
	List(ctx context.Context) ([]Container, error)
	Inspect(ctx context.Context, id string) (Container, error)
	Events(ctx context.Context) (<-chan Event, <-chan error)
	Close() error
}

// Container is the slice of Docker info blocky needs.
type Container struct {
	ID      string
	Name    string
	Image   string
	PID     int
	Labels  map[string]string
	Status  string // running|exited|...
	Created time.Time
}

// Event is a container lifecycle transition we care about.
type Event struct {
	Action string // start|die|destroy|update
	ID     string
	Name   string
	Labels map[string]string
}

type sdkClient struct {
	c *dockerclient.Client
}

// New connects to dockerHost (e.g. "unix:///var/run/docker.sock").
func New(dockerHost string) (Client, error) {
	c, err := dockerclient.NewClientWithOpts(
		dockerclient.WithHost(dockerHost),
		dockerclient.WithAPIVersionNegotiation(),
	)
	if err != nil {
		return nil, fmt.Errorf("docker client: %w", err)
	}
	return &sdkClient{c: c}, nil
}

func (s *sdkClient) Close() error { return s.c.Close() }

func (s *sdkClient) List(ctx context.Context) ([]Container, error) {
	cs, err := s.c.ContainerList(ctx, container.ListOptions{All: false})
	if err != nil {
		return nil, fmt.Errorf("container list: %w", err)
	}
	out := make([]Container, 0, len(cs))
	for _, c := range cs {
		full, err := s.Inspect(ctx, c.ID)
		if err != nil {
			// Container may have died between list and inspect; skip.
			continue
		}
		out = append(out, full)
	}
	return out, nil
}

func (s *sdkClient) Inspect(ctx context.Context, id string) (Container, error) {
	info, err := s.c.ContainerInspect(ctx, id)
	if err != nil {
		return Container{}, fmt.Errorf("inspect %s: %w", id, err)
	}
	name := strings.TrimPrefix(info.Name, "/")
	var created time.Time
	if info.Created != "" {
		// Docker emits RFC3339Nano; ignore parse errors so a malformed value
		// just leaves Created zero.
		created, _ = time.Parse(time.RFC3339Nano, info.Created)
	}
	image := ""
	if info.Config != nil {
		image = info.Config.Image
	}
	return Container{
		ID:      info.ID,
		Name:    name,
		Image:   image,
		PID:     info.State.Pid,
		Labels:  info.Config.Labels,
		Status:  info.State.Status,
		Created: created,
	}, nil
}

func (s *sdkClient) Events(ctx context.Context) (<-chan Event, <-chan error) {
	out := make(chan Event, 32)
	errCh := make(chan error, 1)

	f := filters.NewArgs()
	f.Add("type", "container")
	f.Add("event", "start")
	f.Add("event", "die")
	f.Add("event", "destroy")
	f.Add("event", "update")

	go func() {
		defer close(out)
		defer close(errCh)

		msgs, errs := s.c.Events(ctx, events.ListOptions{Filters: f})
		for {
			select {
			case <-ctx.Done():
				return
			case m, ok := <-msgs:
				if !ok {
					return
				}
				out <- Event{
					Action: string(m.Action),
					ID:     m.Actor.ID,
					Name:   m.Actor.Attributes["name"],
					Labels: m.Actor.Attributes,
				}
			case e, ok := <-errs:
				if !ok || e == nil {
					return
				}
				errCh <- e
				return
			}
		}
	}()
	return out, errCh
}
