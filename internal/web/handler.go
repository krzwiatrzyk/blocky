// Package web serves the blocky dashboard at `/`.
//
// The dashboard is a small templ-rendered HTML page driven by HTMX over a
// WebSocket. It surfaces:
//
//   - Dashboard at  `/`              — KPI tiles + chart + donut + container
//     list + live recent traffic + top destinations.
//   - Containers at `/containers`    — focused container list with status
//     filter; polled every 10s.
//   - Live traffic  `/traffic`       — full-screen chart + recent table +
//     filter rail.
//   - DNS at        `/dns`           — chart + UDP/53 live table + IP→domain
//     cache snapshot.
//   - Rules at      `/rules`         — read-only allow-list view.
//   - Settings at   `/settings`      — read-only environment configuration.
//
// All live updates flow through one `/ws` endpoint that subscribes to the
// tap.Hub and writes pre-rendered HTML fragments (htmx OOB swap targets) for
// each passing event. Filters are applied server-side per WS connection so the
// browser only sees what the user asked for.
package web

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	dnscache "blocky/internal/dns"
	"blocky/internal/config"
	"blocky/internal/reconciler"
	"blocky/internal/tap"
	"blocky/internal/web/views"
	"blocky/internal/web/views/components"
	"github.com/a-h/templ"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Handler owns the dashboard's HTTP handlers. One instance per daemon.
type Handler struct {
	log   zerolog.Logger
	hub   *tap.Hub
	rec   *reconciler.Reconciler
	cache *dnscache.Cache
	cfg   config.Config
}

// New builds a Handler. All collaborators are required.
func New(log zerolog.Logger, hub *tap.Hub, rec *reconciler.Reconciler, cache *dnscache.Cache, cfg config.Config) *Handler {
	return &Handler{log: log, hub: hub, rec: rec, cache: cache, cfg: cfg}
}

// Register mounts the dashboard routes on the gin engine.
func (h *Handler) Register(r *gin.Engine) {
	r.GET("/", h.Index)
	r.GET("/containers", h.ContainersPage)
	r.GET("/containers/fragment", h.ContainersFragment)
	r.GET("/traffic", h.TrafficPage)
	r.GET("/dns", h.DNSPage)
	r.GET("/dns/cache", h.CacheSnapshot)
	r.GET("/rules", h.RulesPage)
	r.GET("/settings", h.SettingsPage)
	r.GET("/overview", h.Overview)
	r.GET("/ws", h.WS)
	r.StaticFS("/static", StaticFileSystem())
}

// ─────────────────────────── Page renderers ──────────────────────────────

// Index serves the / dashboard.
func (h *Handler) Index(c *gin.Context) {
	rng := rangeOf(c)
	agg := h.hub.Aggregate(tap.AggregateOptions{Window: rangeWindow(rng), ExcludeDNS: true})
	containers := h.containerRows(agg)
	render(c, views.Dashboard(views.DashboardData{
		Meta: views.PageMeta{
			View:   "dashboard",
			Title:  "Overview",
			Crumbs: h.crumbs(),
			Range:  rng,
			Live:   true,
		},
		Agg:        agg,
		Containers: containers,
	}))
}

// ContainersPage serves /containers.
func (h *Handler) ContainersPage(c *gin.Context) {
	filter := c.DefaultQuery("status", "all")
	rows := h.filteredContainers(filter)
	render(c, views.Containers(views.ContainersData{
		Meta: views.PageMeta{
			View:   "containers",
			Title:  "Containers",
			Crumbs: h.crumbs(),
			Range:  rangeOf(c),
		},
		Containers: rows,
		Filter:     filter,
	}))
}

// ContainersFragment returns just the container list <div> body for the
// /containers page's HTMX poll.
func (h *Handler) ContainersFragment(c *gin.Context) {
	filter := c.DefaultQuery("status", "all")
	rows := h.filteredContainers(filter)
	render(c, components.ContainerList(rows))
}

// TrafficPage serves /traffic.
func (h *Handler) TrafficPage(c *gin.Context) {
	render(c, views.TrafficLive(views.PageMeta{
		View:   "traffic",
		Title:  "Live traffic",
		Crumbs: h.crumbs(),
		Range:  rangeOf(c),
		Live:   true,
	}))
}

// DNSPage serves /dns.
func (h *Handler) DNSPage(c *gin.Context) {
	render(c, views.DNS(views.PageMeta{
		View:   "dns",
		Title:  "DNS",
		Crumbs: h.crumbs(),
		Range:  rangeOf(c),
		Live:   true,
	}))
}

// RulesPage serves /rules.
func (h *Handler) RulesPage(c *gin.Context) {
	cs := h.rec.Snapshot()
	sort.Slice(cs, func(i, j int) bool { return cs[i].Name < cs[j].Name })
	render(c, views.Rules(views.RulesData{
		Meta: views.PageMeta{
			View:   "rules",
			Title:  "Rules",
			Crumbs: h.crumbs(),
			Range:  rangeOf(c),
		},
		Containers: cs,
	}))
}

// SettingsPage serves /settings.
func (h *Handler) SettingsPage(c *gin.Context) {
	render(c, views.Settings(views.SettingsData{
		Meta: views.PageMeta{
			View:   "settings",
			Title:  "Settings",
			Crumbs: h.crumbs(),
			Range:  rangeOf(c),
		},
		Cfg: h.cfg,
	}))
}

// Overview returns the polled OOB-swap fragment that refreshes the dashboard's
// KPIs / donut / containers list / top destinations.
func (h *Handler) Overview(c *gin.Context) {
	rng := rangeOf(c)
	agg := h.hub.Aggregate(tap.AggregateOptions{Window: rangeWindow(rng), ExcludeDNS: true})
	containers := h.containerRows(agg)
	render(c, views.OverviewFragment(views.DashboardData{
		Agg:        agg,
		Containers: containers,
	}))
}

// CacheSnapshot returns the rendered rows for the IP→domain cache table.
// Raw cache entries are keyed by (ifindex, ip) → name; one DNS query often
// returns several A records for the same name, so the table groups by
// (container, name) and shows the list of IPs to avoid the appearance of
// duplicate rows.
func (h *Handler) CacheSnapshot(c *gin.Context) {
	snap := h.cache.SnapshotAll()
	type key struct{ container, name string }
	grouped := map[key]*components.CacheEntry{}
	order := []key{}
	for _, e := range snap {
		k := key{container: h.containerLabelFor(e.Ifindex), name: e.Name}
		if existing, ok := grouped[k]; ok {
			existing.IPs = append(existing.IPs, e.IP)
			continue
		}
		grouped[k] = &components.CacheEntry{
			Container: k.container,
			Name:      k.name,
			IPs:       []string{e.IP},
		}
		order = append(order, k)
	}
	entries := make([]components.CacheEntry, 0, len(order))
	for _, k := range order {
		entries = append(entries, *grouped[k])
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Container != entries[j].Container {
			return entries[i].Container < entries[j].Container
		}
		return entries[i].Name < entries[j].Name
	})
	for i := range entries {
		sort.Strings(entries[i].IPs)
	}
	render(c, components.CacheTBody(entries))
}

// ─────────────────────────── Helpers ─────────────────────────────────────

func (h *Handler) containerRows(agg tap.Aggregate) []components.ContainerRow {
	return components.JoinContainers(h.rec.Snapshot(), agg.PerContainer)
}

// rangeOf reads the ?range= query param, falling back to "1h". Unknown values
// also fall back so a typo in a bookmarked URL doesn't break the page.
func rangeOf(c *gin.Context) string {
	r := c.DefaultQuery("range", "1h")
	if _, ok := rangeWindows[r]; !ok {
		return "1h"
	}
	return r
}

var rangeWindows = map[string]time.Duration{
	"5m":  5 * time.Minute,
	"15m": 15 * time.Minute,
	"1h":  time.Hour,
	"6h":  6 * time.Hour,
	"24h": 24 * time.Hour,
}

// rangeWindow maps a range label to the corresponding aggregator window.
func rangeWindow(r string) time.Duration {
	if d, ok := rangeWindows[r]; ok {
		return d
	}
	return time.Hour
}

func (h *Handler) filteredContainers(filter string) []components.ContainerRow {
	agg := h.hub.Aggregate(tap.AggregateOptions{Window: time.Hour, ExcludeDNS: true})
	rows := h.containerRows(agg)
	if filter == "" || filter == "all" {
		return rows
	}
	out := rows[:0]
	for _, r := range rows {
		switch filter {
		case "active":
			if r.Container.Status == "active" {
				out = append(out, r)
			}
		case "failed":
			if strings.HasPrefix(r.Container.Status, "failed") {
				out = append(out, r)
			}
		case "skipped":
			if strings.HasPrefix(r.Container.Status, "skipped") {
				out = append(out, r)
			}
		}
	}
	return out
}

func (h *Handler) containerLabelFor(ifindex int) string {
	c, ok := h.rec.LookupByIfindex(ifindex)
	if !ok {
		return fmt.Sprintf("if%d", ifindex)
	}
	if c.Name != "" {
		return c.Name
	}
	if len(c.ID) >= 12 {
		return c.ID[:12]
	}
	return c.ID
}

// crumbs builds the monospace breadcrumb shown under each page title.
// "docker.host.local · N containers · monitoring" matches the design.
func (h *Handler) crumbs() string {
	cs := h.rec.Snapshot()
	monitored := 0
	for _, c := range cs {
		if c.Status == "active" {
			monitored++
		}
	}
	return fmt.Sprintf("docker.host.local · %d containers · monitoring", monitored)
}

func render(c *gin.Context, comp templ.Component) {
	c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusOK)
	_ = comp.Render(c.Request.Context(), c.Writer)
}
