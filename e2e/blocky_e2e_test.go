package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"runtime"
	"testing"
	"time"

	"blocky/e2e/helpers"
	"blocky/internal/types"
	"github.com/gorilla/websocket"
)

const apiAddr = "127.0.0.1:18080"

// TestNoLabelPassesThrough verifies the default behaviour: a container without
// any blocky labels can reach any HTTPS site. This is the safety-net case.
func TestNoLabelPassesThrough(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx := context.Background()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-nolabel", helpers.CurlOptions{})

	for _, target := range []string{"https://www.google.com", "https://www.bing.com"} {
		code, out := helpers.Curl(ctx, c, target)
		if code != 0 {
			t.Errorf("expected curl %s to succeed (no label policy), got exit=%d out=%q",
				target, code, out)
		}
	}
}

// TestLabeledContainerAllowsListedAndBlocksOthers is the headline test: with
// blocky.allowed-https-domains=www.google.com on a container, google
// succeeds and bing fails.
func TestLabeledContainerAllowsListedAndBlocksOthers(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx := context.Background()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-labeled",
		helpers.CurlOptions{Domains: "www.google.com"})

	if code, out := helpers.Curl(ctx, c, "https://www.google.com"); code != 0 {
		t.Errorf("expected curl https://www.google.com to succeed (allowed by policy), got exit=%d out=%q",
			code, out)
	}
	if code, _ := helpers.Curl(ctx, c, "https://www.bing.com"); code == 0 {
		t.Errorf("expected curl https://www.bing.com to FAIL (not in allowlist), got exit=0")
	}
}

// TestTapStreamObservesVerdicts opens the /v1/tap WebSocket and verifies that
// blocked + allowed flows are observed with the expected verdicts.
func TestTapStreamObservesVerdicts(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-tap",
		helpers.CurlOptions{Domains: "www.google.com"})

	events := subscribeTap(ctx, t)
	time.Sleep(500 * time.Millisecond) // let ws connect

	// Trigger one allowed flow and one blocked flow.
	_, _ = helpers.Curl(ctx, c, "https://www.google.com")
	_, _ = helpers.Curl(ctx, c, "https://www.bing.com")

	var (
		sawAllow = false
		sawDrop  = false
	)
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && (!sawAllow || !sawDrop) {
		select {
		case ev := <-events:
			b, _ := json.Marshal(ev)
			t.Logf("event: %s", string(b))
			if ev.Verdict == types.VerdictAllow && ev.Name == "www.google.com" {
				sawAllow = true
			}
			if ev.Verdict == types.VerdictDrop && ev.Name == "www.bing.com" {
				sawDrop = true
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if !sawAllow {
		t.Errorf("did not observe ALLOW for www.google.com on tap")
	}
	if !sawDrop {
		t.Errorf("did not observe DROP for www.bing.com on tap")
	}
}

// TestTapStreamObservesDNSDomain verifies that DNS lookups surface their
// queried domain in the tap stream (reason=dns-exempt with name populated).
func TestTapStreamObservesDNSDomain(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// A label is required so the BPF program is attached to this container.
	// Use an external resolver so the DNS query traverses the veth — Docker's
	// embedded 127.0.0.11 resolver keeps traffic on loopback inside the netns
	// where the BPF program can't see it.
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-dns", helpers.CurlOptions{
		Domains: "www.google.com",
		DNS:     []string{"8.8.8.8", "1.1.1.1"},
	})

	events := subscribeTap(ctx, t)
	time.Sleep(500 * time.Millisecond)

	_, _ = helpers.Curl(ctx, c, "https://www.google.com")

	saw := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !saw {
		select {
		case ev := <-events:
			if ev.Reason == types.ReasonDNSExempt && ev.Name == "www.google.com" {
				saw = true
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if !saw {
		t.Errorf("did not observe DNS event with name=www.google.com")
	}
}

// subscribeTap dials /v1/tap and returns a channel of decoded FlowEvents.
// The goroutine terminates when ctx is cancelled or the connection closes.
func subscribeTap(ctx context.Context, t *testing.T) chan types.FlowEvent {
	t.Helper()
	events := make(chan types.FlowEvent, 32)
	go func() {
		u := url.URL{Scheme: "ws", Host: apiAddr, Path: "/v1/tap"}
		conn, _, err := websocket.DefaultDialer.DialContext(ctx, u.String(), nil)
		if err != nil {
			t.Logf("ws dial: %v", err)
			return
		}
		defer func() { _ = conn.Close() }()
		go func() {
			<-ctx.Done()
			_ = conn.Close()
		}()
		for {
			var ev types.FlowEvent
			if err := conn.ReadJSON(&ev); err != nil {
				return
			}
			select {
			case events <- ev:
			case <-ctx.Done():
				return
			}
		}
	}()
	return events
}

// TestPortAllowlistBlocksUnlistedPort exercises the port-only mode: a
// container with `allowed-ports=53,443` (no domain list) should reach any
// HTTPS site on port 443 yet have outbound TCP to a non-listed port dropped
// by BPF with reason=port-blocked.
func TestPortAllowlistBlocksUnlistedPort(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-port-only", helpers.CurlOptions{
		Ports: "53,443",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	})

	events := subscribeTap(ctx, t)
	time.Sleep(500 * time.Millisecond)

	// 443 is in the list and SNI is not gated ⇒ any HTTPS site OK.
	if code, out := helpers.Curl(ctx, c, "https://www.bing.com"); code != 0 {
		t.Errorf("expected https://www.bing.com to succeed in port-only mode, got exit=%d out=%q", code, out)
	}
	// 8443 is not in the list ⇒ BPF should drop on TCP SYN.
	if code, _ := helpers.Curl(ctx, c, "https://www.bing.com:8443"); code == 0 {
		t.Errorf("expected https://www.bing.com:8443 to FAIL (port 8443 not in allowlist)")
	}

	saw := false
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) && !saw {
		select {
		case ev := <-events:
			if ev.Reason == types.ReasonPortBlocked && ev.DstPort == 8443 {
				saw = true
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if !saw {
		t.Errorf("expected to observe a port-blocked event for dport=8443 on tap")
	}
}

// TestPortAndDomainsCompose: when both labels are set, port allowlist gates
// first, then SNI filter applies on tcp/443.
func TestPortAndDomainsCompose(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-port-and-domains", helpers.CurlOptions{
		Ports:   "53,443",
		Domains: "www.google.com",
		DNS:     []string{"8.8.8.8", "1.1.1.1"},
	})

	if code, out := helpers.Curl(ctx, c, "https://www.google.com"); code != 0 {
		t.Errorf("expected https://www.google.com to succeed, got exit=%d out=%q", code, out)
	}
	if code, _ := helpers.Curl(ctx, c, "https://www.bing.com"); code == 0 {
		t.Errorf("expected https://www.bing.com to FAIL (SNI filter still applies)")
	}
}

// TestDNSDropsWhenPortListLacksIt: with `allowed-ports=443` and no 53 in
// the list, hostname resolution drops; curl can't connect to anything.
func TestDNSDropsWhenPortListLacksIt(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-no-dns", helpers.CurlOptions{
		Ports: "443",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	})

	if code, _ := helpers.Curl(ctx, c, "https://www.google.com"); code == 0 {
		t.Errorf("expected curl to fail (DNS dropped because 53 not in allowlist), got exit=0")
	}
}

// TestTapEnrichesIPWithDNSName: in port-only mode (no SNI filter), the flow
// event for tcp/443 carries no kernel-side name. The hub's DNS cache must
// fill it in based on the resolution observed earlier on udp/53.
func TestTapEnrichesIPWithDNSName(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-enrich", helpers.CurlOptions{
		Ports: "53,443",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	})

	events := subscribeTap(ctx, t)
	time.Sleep(500 * time.Millisecond)

	if code, out := helpers.Curl(ctx, c, "https://www.google.com"); code != 0 {
		t.Errorf("curl https://www.google.com failed in port-only mode: exit=%d out=%q", code, out)
	}

	enriched := false
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) && !enriched {
		select {
		case ev := <-events:
			// Looking for a port-allowed event on tcp/443 whose name was
			// enriched (not produced by SNI parsing, since SNI is disabled
			// in port-only mode).
			if ev.Reason == types.ReasonPortAllowed &&
				ev.DstPort == 443 && ev.Name == "www.google.com" {
				enriched = true
			}
		case <-time.After(500 * time.Millisecond):
		}
	}
	if !enriched {
		t.Errorf("expected tap to surface tcp/443 flow enriched with Name=www.google.com from DNS cache")
	}
}

func skipIfNotLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skipf("e2e requires Linux, got %s", runtime.GOOS)
	}
}

// Ensure fmt import isn't elided when only used in error messages by test build.
var _ = fmt.Sprintf
