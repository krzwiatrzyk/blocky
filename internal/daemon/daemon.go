// Package daemon is the composition root for `blocky run`.
//
// It wires the DI graph (samber/do), starts the long-running goroutines under
// an errgroup, and orchestrates graceful shutdown on context cancellation.
package daemon

import (
	"context"
	"errors"
	"fmt"

	"blocky/internal/api"
	"blocky/internal/bpf"
	"blocky/internal/config"
	dnscache "blocky/internal/dns"
	"blocky/internal/docker"
	"blocky/internal/reconciler"
	"blocky/internal/tap"
	"github.com/rs/zerolog"
	"github.com/samber/do/v2"
	"golang.org/x/sync/errgroup"
)

// Run constructs the daemon's component graph and blocks until ctx is canceled.
func Run(ctx context.Context, cfg config.Config, log zerolog.Logger) error {
	i := do.New()
	defer func() {
		if err := i.Shutdown(); err != nil {
			log.Error().Err(err).Msg("samber/do shutdown error")
		}
	}()

	do.ProvideValue(i, cfg)
	do.ProvideValue(i, log)

	// BPF Manager: pulls in eBPF program; needs CAP_BPF + CAP_NET_ADMIN.
	bpfMgr, err := bpf.New(log)
	if err != nil {
		return fmt.Errorf("bpf manager: %w", err)
	}
	defer func() { _ = bpfMgr.Close() }()
	do.ProvideValue(i, bpfMgr)

	// Docker client.
	dc, err := docker.New(cfg.DockerHost)
	if err != nil {
		return fmt.Errorf("docker client: %w", err)
	}
	defer func() { _ = dc.Close() }()
	do.ProvideValue(i, dc)

	// DNS cache: per-container IP→domain LRU, populated from BPF response events,
	// consumed by the tap hub to enrich flow events with the queried domain.
	dnsCache := dnscache.New(cfg.DNSCachePerContainer)
	do.ProvideValue(i, dnsCache)

	// Flow cache: bounded ring of recent decorated flow events; powers the
	// /v1/flows JSON endpoint and the dashboard WS replay-on-connect path.
	flowCache := tap.NewFlowCache(cfg.FlowCacheSize)
	do.ProvideValue(i, flowCache)

	// Reconciler: docker events → bpf attach/detach; also forgets DNS cache
	// entries on detach so a reused ifindex doesn't surface stale mappings.
	rec := reconciler.New(cfg, log, dc, bpfMgr, dnsCache)
	do.ProvideValue(i, rec)

	// Tap hub: flow events + dns-resolved events → fan-out to WS subscribers.
	hub := tap.New(bpfMgr.Events(), bpfMgr.ResolvedNames(), dnsCache, flowCache, rec, log)
	do.ProvideValue(i, hub)

	// HTTP/WS server.
	srv := api.New(cfg, log, rec, hub, dnsCache, flowCache)
	do.ProvideValue(i, srv)

	log.Info().Str("api_addr", cfg.APIAddr).Str("docker_host", cfg.DockerHost).
		Msg("blocky daemon starting")

	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() error { return hub.Run(gctx) })
	g.Go(func() error { return rec.Run(gctx) })
	g.Go(func() error { return srv.Run(gctx) })

	err = g.Wait()
	switch {
	case err == nil, errors.Is(err, context.Canceled):
		log.Info().Msg("blocky daemon stopped")
		return nil
	default:
		return fmt.Errorf("daemon: %w", err)
	}
}
