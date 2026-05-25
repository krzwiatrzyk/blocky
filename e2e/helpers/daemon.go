// Package helpers builds testcontainers + daemon lifecycle for e2e tests.
package helpers

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Daemon runs the blocky binary under sudo for the duration of a test session.
type Daemon struct {
	APIAddr string
	cmd     *exec.Cmd
	stdout  *bytes.Buffer
	stderr  *bytes.Buffer
}

// StartDaemon launches sudo ./blocky run and waits until /v1/health responds.
// The binary must already be built at the project root (use task build).
func StartDaemon(t *testing.T, apiAddr string) *Daemon {
	t.Helper()
	if apiAddr == "" {
		apiAddr = "127.0.0.1:18080"
	}
	binary := findBinary(t)

	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}

	cmd := exec.Command( //nolint:gosec // test-only helper, binary path is from this repo
		"sudo", "-n", "-E",
		"env",
		"BLOCKY_API_ADDR="+apiAddr,
		"BLOCKY_LOG_FORMAT=console",
		"BLOCKY_LOG_LEVEL=debug",
		binary, "run",
	)
	cmd.Stdout = io.MultiWriter(stdout, os.Stderr)
	cmd.Stderr = io.MultiWriter(stderr, os.Stderr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}

	d := &Daemon{APIAddr: apiAddr, cmd: cmd, stdout: stdout, stderr: stderr}
	t.Cleanup(d.Stop)

	if err := d.waitReady(20 * time.Second); err != nil {
		t.Fatalf("daemon did not become ready: %v\nstdout: %s\nstderr: %s",
			err, stdout.String(), stderr.String())
	}
	return d
}

// Stop kills the daemon and waits for sudo to settle.
func (d *Daemon) Stop() {
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	pgid, err := syscall.Getpgid(d.cmd.Process.Pid)
	if err == nil {
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	} else {
		_ = d.cmd.Process.Signal(syscall.SIGTERM)
	}
	// Wait briefly, then SIGKILL if needed.
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
	}
}

func (d *Daemon) waitReady(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	url := "http://" + d.APIAddr + "/v1/health"
	client := &http.Client{Timeout: 1 * time.Second}
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("timeout after %s", timeout)
}

// findBinary returns the absolute path to ./blocky relative to the project root.
func findBinary(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	// e2e package lives at <root>/e2e/...
	root := wd
	for {
		_, err := os.Stat(filepath.Join(root, "go.mod"))
		if err == nil {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatalf("could not locate go.mod from %s", wd)
		}
		root = parent
	}
	bin := filepath.Join(root, "blocky")
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("blocky binary not found at %s — run `task build` first", bin)
	}
	return bin
}

// Stdout returns daemon stdout captured so far (for test debugging).
func (d *Daemon) Stdout() string { return d.stdout.String() }

// Stderr returns daemon stderr captured so far (for test debugging).
func (d *Daemon) Stderr() string { return d.stderr.String() }

// CheckSudoNoPassword fails the test fast if `sudo -n true` doesn't work.
func CheckSudoNoPassword(t *testing.T) {
	t.Helper()
	out, err := exec.Command("sudo", "-n", "true").CombinedOutput()
	if err != nil {
		t.Skipf("sudo -n true failed (need passwordless sudo for e2e): %v: %s",
			err, strings.TrimSpace(string(out)))
	}
}
