package helpers

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// CurlOptions controls how StartCurlContainer composes the test container.
type CurlOptions struct {
	// Domains becomes the blocky.allowed-https-domains label (empty ⇒ unset).
	Domains string
	// Ports becomes the blocky.allowed-ports label (empty ⇒ unset).
	Ports string
	// DNS overrides Docker's embedded resolver (127.0.0.11). The embedded
	// resolver intercepts queries via iptables inside the container's netns,
	// so DNS never traverses the veth — supply an external resolver here
	// when the test needs to observe DNS traffic in the BPF tap.
	DNS []string
}

// StartCurlContainer launches a long-lived alpine/curl container with the
// configured labels and DNS. The container sleeps so the caller can docker-exec
// curls against it. Labels drive blocky's docker-watcher when the container
// starts.
func StartCurlContainer(ctx context.Context, t *testing.T, name string, opts CurlOptions) testcontainers.Container {
	t.Helper()

	// Every test container opts in to blocky. The opt-in label is required as
	// of the blocky.enabled change — without it the container would be ignored
	// by the reconciler regardless of the other policy labels.
	labels := map[string]string{"blocky.enabled": "true"}
	if opts.Domains != "" {
		labels["blocky.allowed-https-domains"] = opts.Domains
	}
	if opts.Ports != "" {
		labels["blocky.allowed-ports"] = opts.Ports
	}

	req := testcontainers.ContainerRequest{
		Image:      "curlimages/curl:8.5.0",
		Entrypoint: []string{"sleep"},
		Cmd:        []string{"600"},
		Name:       name,
		Labels:     labels,
		WaitingFor: wait.ForExec([]string{"true"}).
			WithStartupTimeout(15 * time.Second),
	}
	if len(opts.DNS) > 0 {
		addrs := make([]netip.Addr, 0, len(opts.DNS))
		for _, s := range opts.DNS {
			a, err := netip.ParseAddr(s)
			if err != nil {
				t.Fatalf("StartCurlContainer: invalid dns address %q: %v", s, err)
			}
			addrs = append(addrs, a)
		}
		req.HostConfigModifier = func(hc *container.HostConfig) {
			hc.DNS = addrs
		}
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
		Reuse:            false,
	})
	if err != nil {
		t.Fatalf("start curl container %s: %v", name, err)
	}
	t.Cleanup(func() {
		_ = c.Terminate(context.Background())
	})

	// Give blocky a moment to observe the docker start event and attach.
	// In practice the attach happens within tens of milliseconds.
	time.Sleep(500 * time.Millisecond)

	return c
}

// Curl runs `curl -sSf -m 10 <url>` inside the container and returns the exit code.
func Curl(ctx context.Context, c testcontainers.Container, url string) (int, string) {
	cmd := []string{"curl", "-sSf", "-m", "10", "-o", "/dev/null", "-w", "%{http_code}", url}
	exitCode, reader, err := c.Exec(ctx, cmd)
	output := ""
	if reader != nil {
		buf := make([]byte, 4096)
		n, _ := reader.Read(buf)
		output = string(buf[:n])
	}
	if err != nil {
		return -1, output
	}
	return exitCode, output
}
