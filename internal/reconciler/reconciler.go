// Package reconciler bridges Docker events to the BPF manager.
//
// On startup it lists running containers and attaches policy to those carrying
// blocky.allowed-https-domains and/or blocky.allowed-ports. While running it
// consumes the Docker event stream and updates BPF state in response.
package reconciler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"blocky/internal/bpf"
	"blocky/internal/config"
	dnscache "blocky/internal/dns"
	"blocky/internal/docker"
	"blocky/internal/netns"
	"blocky/internal/policy"
	"blocky/internal/types"
	"github.com/rs/zerolog"
)

// Reconciler maintains the registry of attached containers and drives the BPF
// manager from Docker events.
type Reconciler struct {
	cfg      config.Config
	log      zerolog.Logger
	docker   docker.Client
	bpf      *bpf.Manager
	dnsCache *dnscache.Cache

	mu        sync.RWMutex
	byID      map[string]*types.Container
	byIfindex map[int]string // ifindex -> container ID
}

// New builds a Reconciler. dnsCache may be nil — when supplied, its per-container
// entries are forgotten on detach so a recycled ifindex never surfaces a stale
// IP→domain mapping from a previous container.
func New(cfg config.Config, log zerolog.Logger, dc docker.Client, bm *bpf.Manager,
	dnsCache *dnscache.Cache) *Reconciler {
	return &Reconciler{
		cfg:       cfg,
		log:       log,
		docker:    dc,
		bpf:       bm,
		dnsCache:  dnsCache,
		byID:      map[string]*types.Container{},
		byIfindex: map[int]string{},
	}
}

// Run blocks until ctx is canceled. Returns on docker event-stream errors only
// if the daemon's own ctx isn't canceled.
func (r *Reconciler) Run(ctx context.Context) error {
	if err := r.seed(ctx); err != nil {
		r.log.Error().Err(err).Msg("initial seed encountered errors")
	}

	for {
		err := r.consumeEvents(ctx)
		if err == nil {
			// consumeEvents returns nil only when ctx is canceled.
			return nil
		}
		if ctx.Err() != nil {
			// Returning nil here is intentional: a context cancellation is
			// the requested shutdown path, not an unhandled failure.
			return nil //nolint:nilerr // ctx.Err() drove the loop exit
		}
		r.log.Error().Err(err).Msg("docker event stream broke; reconnecting in 2s")
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
			return nil
		}
	}
}

func (r *Reconciler) seed(ctx context.Context) error {
	containers, err := r.docker.List(ctx)
	if err != nil {
		return fmt.Errorf("docker list: %w", err)
	}
	r.log.Info().Int("count", len(containers)).Msg("seeding from running containers")
	for _, c := range containers {
		r.applyAttach(ctx, c)
	}
	return nil
}

func (r *Reconciler) consumeEvents(ctx context.Context) error {
	events, errs := r.docker.Events(ctx)
	for {
		select {
		case <-ctx.Done():
			return nil
		case e, ok := <-events:
			if !ok {
				return errors.New("docker events channel closed")
			}
			r.handleEvent(ctx, e)
		case err, ok := <-errs:
			if !ok {
				return errors.New("docker errors channel closed")
			}
			return err
		}
	}
}

func (r *Reconciler) handleEvent(ctx context.Context, e docker.Event) {
	switch e.Action {
	case "start":
		c, err := r.docker.Inspect(ctx, e.ID)
		if err != nil {
			r.log.Warn().Err(err).Str("id", e.ID).Msg("inspect failed on start")
			return
		}
		r.applyAttach(ctx, c)
	case "update":
		c, err := r.docker.Inspect(ctx, e.ID)
		if err != nil {
			return
		}
		r.applyAttach(ctx, c)
	case "die", "destroy":
		r.applyDetach(e.ID)
	}
}

func (r *Reconciler) applyAttach(_ context.Context, c docker.Container) {
	// blocky.enabled is the opt-in marker. Without it we don't manage the
	// container at all — no record, no BPF attach. This matches what an
	// operator expects: a vanilla container should be invisible to blocky
	// unless they've explicitly opted in.
	if !policy.IsEnabled(c.Labels[policy.LabelKeyEnabled]) {
		return
	}

	domainsLabel := c.Labels[policy.LabelKeyDomains]
	portsLabel := c.Labels[policy.LabelKeyPorts]

	pol, err := policy.ParseDomains(domainsLabel, r.cfg.MaxRulesPerContainer)
	if err != nil {
		r.log.Warn().Err(err).Str("container", c.ID).Str("label", domainsLabel).
			Msg("invalid blocky.allowed-https-domains; skipping")
		r.record(c, false, types.Policy{}, "skipped:invalid-label")
		return
	}
	ports, err := policy.ParsePorts(portsLabel)
	if err != nil {
		r.log.Warn().Err(err).Str("container", c.ID).Str("label", portsLabel).
			Msg("invalid blocky.allowed-ports; skipping")
		r.record(c, false, types.Policy{}, "skipped:invalid-label")
		return
	}
	pol.Ports = ports
	// blocky.enabled=true with no rule labels ⇒ observe-only mode: BPF still
	// attaches and every flow surfaces in the UI, but nothing is dropped.
	if !pol.HasRules() {
		pol.Observe = true
	}
	if c.PID <= 0 {
		r.log.Warn().Str("container", c.ID).Msg("container has no PID; skipping")
		r.record(c, false, types.Policy{}, "skipped:no-pid")
		return
	}

	ifindex, err := netns.FindHostVethIfindex(c.PID)
	if err != nil {
		r.log.Warn().Err(err).Str("container", c.ID).Msg("veth lookup failed; skipping")
		r.record(c, true, pol, "failed:veth-not-found")
		return
	}
	if err := r.bpf.Attach(ifindex, pol); err != nil {
		r.log.Error().Err(err).Str("container", c.ID).Int("ifindex", ifindex).
			Msg("bpf attach failed")
		r.record(c, true, pol, "failed:bpf-attach-failed")
		return
	}

	r.mu.Lock()
	rec := &types.Container{
		ID:        c.ID,
		Name:      c.Name,
		Image:     c.Image,
		HasPolicy: true,
		Policy:    pol,
		Ifindex:   ifindex,
		Status:    "active",
		CreatedAt: c.Created,
		UpdatedAt: time.Now(),
	}
	// Reattach: drop old ifindex mapping if any.
	if old, ok := r.byID[c.ID]; ok && old.Ifindex != ifindex {
		delete(r.byIfindex, old.Ifindex)
	}
	r.byID[c.ID] = rec
	r.byIfindex[ifindex] = c.ID
	r.mu.Unlock()

	r.log.Info().Str("container", c.ID).Str("name", c.Name).Int("ifindex", ifindex).
		Strs("exact", pol.Exact).Strs("suffix", pol.Suffix).
		Uints16("ports", pol.Ports).Msg("attached")
}

func (r *Reconciler) applyDetach(id string) {
	r.mu.Lock()
	rec, ok := r.byID[id]
	if ok {
		delete(r.byID, id)
		if rec.Ifindex != 0 {
			delete(r.byIfindex, rec.Ifindex)
		}
	}
	r.mu.Unlock()

	if !ok || rec.Ifindex == 0 {
		return
	}
	if err := r.bpf.Detach(rec.Ifindex); err != nil {
		r.log.Error().Err(err).Str("container", id).Int("ifindex", rec.Ifindex).
			Msg("bpf detach failed")
		return
	}
	if r.dnsCache != nil {
		r.dnsCache.Forget(rec.Ifindex)
	}
	r.log.Info().Str("container", id).Int("ifindex", rec.Ifindex).Msg("detached")
}

func (r *Reconciler) record(c docker.Container, hasPolicy bool, p types.Policy, status string) {
	r.mu.Lock()
	r.byID[c.ID] = &types.Container{
		ID:        c.ID,
		Name:      c.Name,
		Image:     c.Image,
		HasPolicy: hasPolicy,
		Policy:    p,
		Status:    status,
		CreatedAt: c.Created,
		UpdatedAt: time.Now(),
	}
	r.mu.Unlock()
}

// LookupByIfindex implements tap.Registry.
func (r *Reconciler) LookupByIfindex(ifindex int) (types.Container, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.byIfindex[ifindex]
	if !ok {
		return types.Container{}, false
	}
	rec, ok := r.byID[id]
	if !ok {
		return types.Container{}, false
	}
	return *rec, true
}

// Snapshot returns a copy of every known container record. Used by the API.
func (r *Reconciler) Snapshot() []types.Container {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]types.Container, 0, len(r.byID))
	for _, c := range r.byID {
		out = append(out, *c)
	}
	return out
}

// Get returns one container's record by ID.
func (r *Reconciler) Get(id string) (types.Container, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.byID[id]
	if !ok {
		return types.Container{}, false
	}
	return *c, true
}
