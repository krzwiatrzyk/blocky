package web

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"blocky/internal/config"
	"blocky/internal/tap"
	"blocky/internal/types"
	"blocky/internal/web/views"
	"blocky/internal/web/views/components"
	"github.com/a-h/templ"
)

// TestRenderPages renders each top-level view with synthetic data and checks
// that the resulting HTML contains the expected anchoring strings. This is a
// fast smoke test — the goal is to catch templ syntax mistakes and missing
// references; it deliberately does not assert on layout or styling.
func TestRenderPages(t *testing.T) {
	containers := []types.Container{
		{
			ID:        "abc123def4567890",
			Name:      "api-gateway",
			Image:     "nginx:1.27-alpine",
			HasPolicy: true,
			Policy:    types.Policy{Exact: []string{"api.stripe.com"}, Suffix: []string{".amazonaws.com"}, Ports: []uint16{443, 53}},
			Ifindex:   42,
			Status:    "active",
			CreatedAt: time.Now().Add(-26 * time.Hour),
			UpdatedAt: time.Now(),
		},
		{
			ID:        "fedcba0987654321",
			Name:      "scraper-prod",
			Image:     "alpine:3.20",
			HasPolicy: true,
			Policy:    types.Policy{Exact: []string{"news-api.example.com"}},
			Ifindex:   43,
			Status:    "skipped:no-label",
			UpdatedAt: time.Now(),
		},
	}
	agg := tap.Aggregate{
		Window: time.Hour,
		Totals: tap.KpiTotals{
			Total:      1024,
			Allow:      990,
			Block:      34,
			DNS:        128,
			AllowSpark: []float64{1, 2, 3, 4, 5, 4, 3, 2, 1, 5, 4, 3, 6, 7, 8, 5, 4, 3, 2, 1, 6, 7, 8, 9},
			BlockSpark: []float64{0, 0, 1, 0, 0, 1, 0, 2, 1, 0, 0, 0, 1, 0, 0, 2, 0, 1, 0, 0, 0, 1, 0, 0},
			DNSSpark:   []float64{2, 4, 6, 8, 4, 2, 6, 8, 10, 4, 2, 6, 4, 2, 8, 6, 4, 2, 8, 6, 4, 2, 8, 6},
		},
		TopDest: []tap.DestStat{
			{Name: "api.stripe.com", Count: 612, Allow: 612, Block: 0},
			{Name: "telemetry.ads.io", Count: 28, Allow: 0, Block: 28},
		},
		PerContainer: map[string]tap.ContainerStat{
			"api-gateway": {Allow: 500, Block: 3, Spark: []float64{1, 2, 3, 4, 5, 4, 3, 2}},
		},
	}
	rows := components.JoinContainers(containers, agg.PerContainer)

	cases := []struct {
		name        string
		render      func() []byte
		mustContain []string
	}{
		{
			name: "Dashboard",
			render: func() []byte {
				return renderToBytes(t, views.Dashboard(views.DashboardData{
					Meta:       views.PageMeta{View: "dashboard", Title: "Overview", Range: "1h", Live: true},
					Agg:        agg,
					Containers: rows,
				}))
			},
			mustContain: []string{
				"Blocky",                       // brand
				"Overview",                     // header title
				"Total Connections",            // kpi label
				"1,024",                        // formatted total
				"Allow vs Block",               // donut card
				"Containers",                   // container list
				"Recent traffic",               // recent traffic card
				"Top destinations",             // top dest card
				"api-gateway",                  // joined container
				"nginx:1.27-alpine",            // image cell
				`data-view="dashboard"`,          // chart mount (excludes DNS)
				`ws-connect="/ws?view=dashboard"`, // ws subscription
				`hx-get="/overview?range=`,      // poll trigger (range carried in QS)
			},
		},
		{
			name: "ContainersPage",
			render: func() []byte {
				return renderToBytes(t, views.Containers(views.ContainersData{
					Meta:       views.PageMeta{View: "containers", Title: "Containers", Range: "1h"},
					Containers: rows,
					Filter:     "active",
				}))
			},
			mustContain: []string{"Containers", "api-gateway", "scraper-prod", "active"},
		},
		{
			name: "DNS",
			render: func() []byte {
				return renderToBytes(t, views.DNS(views.PageMeta{View: "dns", Title: "DNS", Range: "1h", Live: true}))
			},
			mustContain: []string{"DNS", "Resolved-name cache", `ws-connect="/ws?view=dns"`, `id="cache-tbody"`},
		},
		{
			name: "Rules",
			render: func() []byte {
				return renderToBytes(t, views.Rules(views.RulesData{
					Meta:       views.PageMeta{View: "rules", Title: "Rules", Range: "1h"},
					Containers: containers,
				}))
			},
			mustContain: []string{"Rules", "api-gateway", "api.stripe.com", "*.amazonaws.com"},
		},
		{
			name: "Settings",
			render: func() []byte {
				return renderToBytes(t, views.Settings(views.SettingsData{
					Meta: views.PageMeta{View: "settings", Title: "Settings", Range: "1h"},
					Cfg: config.Config{
						APIAddr: "0.0.0.0:8080", LogLevel: "info", LogFormat: "json",
						DockerHost: "unix:///var/run/docker.sock", MaxRulesPerContainer: 16,
						CTMapSize: 16384, DNSCachePerContainer: 1024, FlowCacheSize: 5000,
					},
				}))
			},
			mustContain: []string{
				"Settings", "BLOCKY_API_ADDR", "0.0.0.0:8080",
				"BLOCKY_LOG_LEVEL", "BLOCKY_FLOW_CACHE_SIZE", "5000",
			},
		},
		{
			name: "TrafficLive",
			render: func() []byte {
				return renderToBytes(t, views.TrafficLive(views.PageMeta{
					View: "traffic", Title: "Live traffic", Range: "1h", Live: true,
				}))
			},
			mustContain: []string{"Live traffic", "Filters", "Verdict", `ws-connect="/ws?view=traffic"`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := string(tc.render())
			for _, want := range tc.mustContain {
				if !strings.Contains(out, want) {
					t.Errorf("rendered HTML missing %q (length=%d)", want, len(out))
				}
			}
		})
	}
}

func renderToBytes(t *testing.T, c templ.Component) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := c.Render(context.Background(), &b); err != nil {
		t.Fatalf("render: %v", err)
	}
	return b.Bytes()
}

// TestCacheTBodyGroupsIPs renders the resolved-name cache template with a
// container that resolved one name to multiple IPs (the typical A-record
// case shown in the screenshots/bugs/ folder) and confirms the row carries
// every IP joined with ", " separators — no duplicate rows.
func TestCacheTBodyGroupsIPs(t *testing.T) {
	entries := []components.CacheEntry{
		{Container: "tests-test-run", Name: "www.google.com", IPs: []string{
			"142.251.150.119", "142.251.152.119", "142.251.153.119", "142.251.154.119",
		}},
	}
	out := string(renderToBytes(t, components.CacheTBody(entries)))
	for _, want := range []string{
		"www.google.com",
		"142.251.150.119", "142.251.152.119", "142.251.153.119", "142.251.154.119",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered cache row missing %q (length=%d)", want, len(out))
		}
	}
	if strings.Count(out, "www.google.com") != 1 {
		t.Errorf("name should appear exactly once, got %d", strings.Count(out, "www.google.com"))
	}
}
