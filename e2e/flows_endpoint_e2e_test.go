package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"blocky/e2e/helpers"
	"blocky/internal/types"
)

// TestFlowsEndpointReturnsCachedEvents exercises the new /v1/flows JSON endpoint
// backed by the in-memory flow cache. It generates traffic, then asserts the
// cache snapshot contains the events with DNS enrichment intact and that Seq
// is monotonically assigned. This is the no-browser-required complement to the
// chromedp dashboard test.
func TestFlowsEndpointReturnsCachedEvents(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-flows-endpoint", helpers.CurlOptions{
		Ports: "53,443",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	})

	if code, out := helpers.Curl(ctx, c, "https://www.google.com"); code != 0 {
		t.Fatalf("curl https://www.google.com failed: exit=%d out=%q", code, out)
	}

	// The hub publishes flow events asynchronously; poll the endpoint until we
	// see the expected enriched event, or time out.
	var sawEnriched bool
	var maxSeen uint64
	var lastFlows []types.FlowEvent
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !sawEnriched {
		flows := fetchFlows(t)
		lastFlows = flows
		for _, ev := range flows {
			if ev.Seq > maxSeen {
				maxSeen = ev.Seq
			}
			if ev.DstPort == 443 && ev.Name == "www.google.com" {
				sawEnriched = true
				break
			}
		}
		if !sawEnriched {
			time.Sleep(250 * time.Millisecond)
		}
	}

	if !sawEnriched {
		t.Fatalf("/v1/flows never returned an enriched TCP/443 event for www.google.com (got %d flows, max Seq=%d)",
			len(lastFlows), maxSeen)
	}

	// Verify Seq strictly increases through the snapshot (oldest-first ordering).
	flows := fetchFlows(t)
	var prev uint64
	for i, ev := range flows {
		if ev.Seq == 0 {
			t.Errorf("flows[%d].Seq = 0 (hub must assign monotonic seq before publishing)", i)
		}
		if ev.Seq <= prev {
			t.Errorf("flows[%d].Seq = %d, want > prev=%d (snapshot must be oldest-first)", i, ev.Seq, prev)
		}
		prev = ev.Seq
	}
}

func fetchFlows(t *testing.T) []types.FlowEvent {
	t.Helper()
	resp, err := http.Get("http://" + apiAddr + "/v1/flows")
	if err != nil {
		t.Fatalf("GET /v1/flows: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/flows: status %d", resp.StatusCode)
	}
	var body struct {
		Flows []types.FlowEvent `json:"flows"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode /v1/flows: %v", err)
	}
	return body.Flows
}
