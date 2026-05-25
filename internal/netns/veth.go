// Package netns finds the host-side ifindex of a container's eth0 veth peer.
//
// Mechanism: enter the container's network namespace (via /proc/<pid>/ns/net),
// look up the link named "eth0" (or "ens0", "enp0" depending on cni; "eth0" is
// Docker's default), read its Link.Attrs().ParentIndex. That is the ifindex of
// the host-side peer that we attach the BPF program to.
//
// Discovery is done from a goroutine locked to a single OS thread, so the
// thread's netns swap stays scoped to that thread.
package netns

import (
	"errors"
	"fmt"
	"runtime"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
)

// Default container-side interface name on Docker bridge / docker_gwbridge networks.
const defaultContainerIface = "eth0"

// FindHostVethIfindex returns the host-side veth ifindex for the container PID.
//
// It tries `eth0` by default; pass extra names via candidates to widen the search.
func FindHostVethIfindex(pid int, candidates ...string) (int, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("invalid pid %d", pid)
	}
	if len(candidates) == 0 {
		candidates = []string{defaultContainerIface}
	}

	// Two channels: one for the result, one for the error. Use a goroutine
	// locked to a single OS thread so the netns switch is scoped.
	type result struct {
		ifindex int
		err     error
	}
	done := make(chan result, 1)

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		host, err := netns.Get()
		if err != nil {
			done <- result{err: fmt.Errorf("get host netns: %w", err)}
			return
		}
		defer func() { _ = host.Close() }()

		target, err := netns.GetFromPid(pid)
		if err != nil {
			done <- result{err: fmt.Errorf("get netns for pid %d: %w", pid, err)}
			return
		}
		defer func() { _ = target.Close() }()

		if err := netns.Set(target); err != nil {
			done <- result{err: fmt.Errorf("enter target netns: %w", err)}
			return
		}
		// Restore host netns no matter what; the os-thread will be discarded
		// anyway when we return without unlocking, but defensive Set is cheap.
		defer func() { _ = netns.Set(host) }()

		var ifindex int
		var firstErr error
		for _, name := range candidates {
			link, err := netlink.LinkByName(name)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			ifindex = link.Attrs().ParentIndex
			if ifindex == 0 {
				firstErr = fmt.Errorf("%s has no ParentIndex (not a veth?)", name)
				continue
			}
			done <- result{ifindex: ifindex}
			return
		}
		if firstErr == nil {
			firstErr = errors.New("no candidate interface found")
		}
		done <- result{err: fmt.Errorf("find host veth for pid %d: %w", pid, firstErr)}
	}()

	r := <-done
	return r.ifindex, r.err
}
