//go:build chromedp_e2e

// Package e2e_test's chromedp-driven dashboard tests verify the live HTML +
// chart rendering paths that the plain JSON e2e tests can't observe.
//
// Gate behind a build tag so the default test target stays fast and lean —
// these tests need a chromium binary and pull in the chromedp dependency tree.
// Run them with:
//
//	go get github.com/chromedp/chromedp
//	go test -tags chromedp_e2e -count=1 ./e2e/...
package e2e_test

import (
	"context"
	"os/exec"
	"testing"
	"time"

	"blocky/e2e/helpers"
	"github.com/chromedp/chromedp"
)

// skipIfNoChromium fails fast (via t.Skip) when no chromium-class binary is on
// PATH — chromedp would otherwise spin trying to launch a non-existent
// browser. Keeping the check here avoids polluting helpers.daemon when
// chromedp is opt-in.
func skipIfNoChromium(t *testing.T) {
	t.Helper()
	for _, name := range []string{"chromium", "chromium-browser", "google-chrome", "chrome"} {
		if _, err := exec.LookPath(name); err == nil {
			return
		}
	}
	t.Skip("no chromium/chrome binary on PATH; install one to run dashboard e2e tests")
}

// TestDashboardRendersRowsChartAndName covers bugs #2, #3, #4, and #5 of the
// improvements pass: it asserts rows render as actual <tr> children of
// #flow-rows (parsing fix), that they stack vertically (CSS sanity), that the
// chart picks up data series after rows arrive (observer + redraw working),
// and that the Name column carries the DNS-enriched hostname (decorate path).
func TestDashboardRendersRowsChartAndName(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	skipIfNoChromium(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-dashboard", helpers.CurlOptions{
		Ports:   "53,443",
		Domains: "www.google.com",
		DNS:     []string{"8.8.8.8", "1.1.1.1"},
	})

	cctx, ccancel := chromedp.NewContext(ctx)
	defer ccancel()

	if err := chromedp.Run(cctx,
		chromedp.Navigate("http://"+apiAddr+"/"),
		chromedp.WaitVisible("#flow-rows", chromedp.ByID),
		chromedp.Sleep(500*time.Millisecond),
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	_, _ = helpers.Curl(ctx, c, "https://www.google.com")
	_, _ = helpers.Curl(ctx, c, "https://www.bing.com")

	// Poll for ≥ 2 <tr> direct children of #flow-rows. If HTMX dropped the
	// <tr> wrapper (the bug this test catches) the selector returns 0 forever.
	var rowCount int
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		_ = chromedp.Run(cctx, chromedp.Evaluate(
			`document.querySelectorAll('#flow-rows > tr').length`, &rowCount))
		if rowCount >= 2 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if rowCount < 2 {
		t.Fatalf("rows: got %d, want ≥2 (HTMX <tr> parsing regressed?)", rowCount)
	}

	// Stacking sanity: first two rows must have different top offsets.
	var stacked bool
	if err := chromedp.Run(cctx, chromedp.Evaluate(`(() => {
		const rs = document.querySelectorAll('#flow-rows > tr');
		if (rs.length < 2) return false;
		return Math.abs(rs[0].getBoundingClientRect().top -
			rs[1].getBoundingClientRect().top) > 0;
	})()`, &stacked)); err != nil {
		t.Fatal(err)
	}
	if !stacked {
		t.Fatal("rows do not stack vertically — CSS or layout regression")
	}

	// uPlot creates one .u-series legend row per series; with traffic the chart
	// should have ≥2 (time axis + ≥1 group).
	var seriesCount int
	_ = chromedp.Run(cctx, chromedp.Evaluate(
		`document.querySelectorAll('.u-legend .u-series').length`, &seriesCount))
	if seriesCount < 2 {
		t.Fatalf("uPlot series: got %d, want ≥2 (time + ≥1 data group)", seriesCount)
	}

	// Name column carries DNS-enriched hostname. Columns after the split are
	// (0)time, (1)container, (2)verdict, (3)proto, (4)src-ip, (5)src-port,
	// (6)dst-ip, (7)dst-port, (8)name, (9)reason — see flow_row.templ.
	var sawName bool
	_ = chromedp.Run(cctx, chromedp.Evaluate(`(() => {
		const rs = document.querySelectorAll('#flow-rows > tr');
		for (const r of rs) {
			const tds = r.querySelectorAll('td');
			if (tds.length >= 9 && tds[8].textContent.includes('www.google.com')) return true;
		}
		return false;
	})()`, &sawName))
	if !sawName {
		t.Fatal("no row with Name=www.google.com — DNS enrichment regressed in UI path")
	}
}

// TestDashboardReplaysHistoryOnConnect ensures the flow-cache snapshot is
// replayed to a new WS subscriber. We generate traffic first, THEN navigate;
// rows from before navigation should be present immediately after the WS
// connects.
func TestDashboardReplaysHistoryOnConnect(t *testing.T) {
	skipIfNotLinux(t)
	helpers.CheckSudoNoPassword(t)
	skipIfNoChromium(t)
	helpers.StartDaemon(t, apiAddr)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	c := helpers.StartCurlContainer(ctx, t, "blocky-e2e-replay", helpers.CurlOptions{
		Ports: "53,443",
		DNS:   []string{"8.8.8.8", "1.1.1.1"},
	})

	// Generate several flows before opening the dashboard.
	for i := 0; i < 5; i++ {
		_, _ = helpers.Curl(ctx, c, "https://www.google.com")
	}
	time.Sleep(time.Second) // let the hub publish + cache all events

	cctx, ccancel := chromedp.NewContext(ctx)
	defer ccancel()

	if err := chromedp.Run(cctx,
		chromedp.Navigate("http://"+apiAddr+"/"),
		chromedp.WaitVisible("#flow-rows", chromedp.ByID),
		chromedp.Sleep(2*time.Second), // give WS handshake + replay loop time
	); err != nil {
		t.Fatalf("navigate: %v", err)
	}

	var rowCount int
	_ = chromedp.Run(cctx, chromedp.Evaluate(
		`document.querySelectorAll('#flow-rows > tr').length`, &rowCount))
	if rowCount < 3 {
		t.Fatalf("rows after replay: got %d, want ≥3 (cache replay regressed?)", rowCount)
	}
}
