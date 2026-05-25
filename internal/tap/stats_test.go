package tap_test

import (
	"testing"
	"time"

	"blocky/internal/tap"
	"blocky/internal/types"
	"github.com/rs/zerolog"
)

// TestAggregateExcludesDNS confirms that ExcludeDNS keeps UDP/53 events out
// of Total/Allow/Block/TopDest/PerContainer, while the DNS-specific counters
// keep tracking them so the dashboard's DNS Queries tile still shows traffic.
func TestAggregateExcludesDNS(t *testing.T) {
	t.Parallel()

	cache := tap.NewFlowCache(64)
	now := time.Now()
	add := func(proto string, dport uint16, verdict types.Verdict, name, container string) {
		cache.Add(types.FlowEvent{
			Timestamp:     now.Add(-time.Second),
			Protocol:      proto,
			DstPort:       dport,
			Verdict:       verdict,
			Name:          name,
			ContainerName: container,
		})
	}
	// Two HTTPS allow + one HTTPS drop + three DNS queries to the same name.
	add("tcp", 443, types.VerdictAllow, "api.stripe.com", "api-gateway")
	add("tcp", 443, types.VerdictAllow, "api.stripe.com", "api-gateway")
	add("tcp", 443, types.VerdictDrop, "ads.example.com", "scraper")
	add("udp", 53, types.VerdictAllow, "api.stripe.com", "api-gateway")
	add("udp", 53, types.VerdictAllow, "api.stripe.com", "api-gateway")
	add("udp", 53, types.VerdictAllow, "api.stripe.com", "api-gateway")

	h := tap.New(nil, nil, nil, cache, nil, zerolog.Nop())
	got := h.Aggregate(tap.AggregateOptions{Window: time.Hour, ExcludeDNS: true})

	if got.Totals.Total != 3 {
		t.Errorf("Total = %d, want 3 (DNS excluded)", got.Totals.Total)
	}
	if got.Totals.Allow != 2 {
		t.Errorf("Allow = %d, want 2", got.Totals.Allow)
	}
	if got.Totals.Block != 1 {
		t.Errorf("Block = %d, want 1", got.Totals.Block)
	}
	if got.Totals.DNS != 3 {
		t.Errorf("DNS = %d, want 3 (always counted)", got.Totals.DNS)
	}
	// Top destinations should only mention the HTTPS targets, not the DNS-only
	// resolution of api.stripe.com.
	for _, d := range got.TopDest {
		if d.Name == "api.stripe.com" && d.Count != 2 {
			t.Errorf("api.stripe.com Count = %d, want 2 (HTTPS only)", d.Count)
		}
	}
	if cs := got.PerContainer["api-gateway"]; cs.Allow != 2 {
		t.Errorf("PerContainer[api-gateway].Allow = %d, want 2", cs.Allow)
	}
	// Without ExcludeDNS the totals include DNS events.
	loose := h.Aggregate(tap.AggregateOptions{Window: time.Hour})
	if loose.Totals.Total != 6 {
		t.Errorf("loose Total = %d, want 6 (DNS included)", loose.Totals.Total)
	}
}
