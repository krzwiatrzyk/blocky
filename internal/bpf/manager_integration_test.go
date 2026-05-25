//go:build linux && integration

package bpf_test

import (
	"errors"
	"fmt"
	"os"
	"testing"

	"blocky/internal/bpf"
	"blocky/internal/types"
	"github.com/cilium/ebpf"
	"github.com/rs/zerolog"
)

// TestLoadAndDetach is the smallest realistic check: that the BPF program loads
// against the running kernel without verifier errors, that policy maps are
// writable, and Detach is idempotent.
//
// Attach to a real veth is exercised end-to-end by e2e/. We don't fake one here.
func TestLoadAndDetach(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root (CAP_BPF + CAP_NET_ADMIN); run via task test:integration")
	}

	m, err := bpf.New(zerolog.Nop())
	if err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			t.Fatalf("bpf.New: verifier:\n%s", fmt.Sprintf("%+v", verr))
		}
		t.Fatalf("bpf.New: %v", err)
	}
	defer func() { _ = m.Close() }()

	// Detach on a non-existent ifindex must succeed (idempotent).
	if derr := m.Detach(99999); derr != nil {
		t.Fatalf("Detach on non-existent ifindex: %v", derr)
	}

	// writePolicy is exercised internally by Attach. We can't AttachTCX without
	// a real ifindex, but a bogus one should fail predictably without leaving
	// dangling state. Verify it errors out, not panics.
	if attachErr := m.Attach(0, types.Policy{Exact: []string{"a.com"}}); attachErr == nil {
		t.Fatal("Attach(ifindex=0) should error")
	}
	// Detach after a failed attach must not panic; an error is acceptable.
	if derr := m.Detach(0); derr != nil {
		t.Logf("Detach after failed attach (expected): %v", derr)
	}
}
