// Package components — helper code for the templ files in this package.
//
// Templ files are templates: small amounts of inline Go are fine, but
// non-trivial computations (SVG paths, percentage math, list slicing) live in
// this regular Go file so the templates stay readable and the math gets
// unit-testable without invoking templ.
package components

import (
	"fmt"
	"math"
	"strings"
	"time"

	"blocky/internal/tap"
	"blocky/internal/types"
)

// SparkPath builds an SVG path "d" for a sparkline given a series of points.
// w / h are the SVG viewport size; the returned strings are (stroke path, area
// fill path) and an empty string is returned for both when len(points) < 2.
func SparkPath(points []float64, w, h int) (line, area string) {
	if len(points) < 2 {
		return "", ""
	}
	maxV := points[0]
	minV := points[0]
	for _, v := range points {
		if v > maxV {
			maxV = v
		}
		if v < minV {
			minV = v
		}
	}
	if maxV == minV {
		// Flat series — draw a midline.
		mid := float64(h) / 2
		return fmt.Sprintf("M0,%.1f L%d,%.1f", mid, w, mid),
			fmt.Sprintf("M0,%.1f L%d,%.1f L%d,%d L0,%d Z", mid, w, mid, w, h, h)
	}
	rng := maxV - minV
	stepX := float64(w) / float64(len(points)-1)
	var b strings.Builder
	for i, v := range points {
		x := float64(i) * stepX
		y := float64(h) - ((v-minV)/rng)*(float64(h)-4) - 2
		if i == 0 {
			fmt.Fprintf(&b, "M%.1f,%.1f", x, y)
		} else {
			fmt.Fprintf(&b, " L%.1f,%.1f", x, y)
		}
	}
	line = b.String()
	area = fmt.Sprintf("%s L%d,%d L0,%d Z", line, w, h, h)
	return line, area
}

// DonutDash computes (dashLen, dashOffset) for an SVG ring segment representing
// pct of the full circumference; remainder is rendered as the gap.
func DonutDash(pct float64, circumference float64) (dash, gap float64) {
	d := math.Max(0, math.Min(circumference, (pct/100)*circumference))
	return d, circumference - d
}

// FormatNumber adds thousands separators in en-US style.
func FormatNumber(n int) string {
	s := fmt.Sprintf("%d", n)
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	var b strings.Builder
	for i, r := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(r)
	}
	out := b.String()
	if neg {
		out = "-" + out
	}
	return out
}

// FormatUptime returns "Nd Mh", "Nh Mm", or "Ns" given a start time. Returns
// "—" when start is the zero value.
func FormatUptime(start time.Time) string {
	if start.IsZero() {
		return "—"
	}
	d := time.Since(start)
	if d < 0 {
		d = 0
	}
	days := int(d / (24 * time.Hour))
	hours := int(d%(24*time.Hour)) / int(time.Hour)
	mins := int(d%time.Hour) / int(time.Minute)
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %02dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %02dm", hours, mins)
	default:
		return fmt.Sprintf("%dm", mins)
	}
}

// FirstUpper returns the first rune of s upper-cased; falls back to "?" when
// s is empty. Used by the favicon-like initial chip in domain rows.
func FirstUpper(s string) string {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "*"), ".")
	if s == "" {
		return "?"
	}
	return strings.ToUpper(string(s[0]))
}

// ShortID returns the first 12 chars of an ID (Docker convention).
func ShortID(id string) string {
	if len(id) >= 12 {
		return id[:12]
	}
	return id
}

// Pct returns 100·numerator/denominator, guarding against zero.
func Pct(num, den int) float64 {
	if den <= 0 {
		return 0
	}
	return 100 * float64(num) / float64(den)
}

// IntsToFloats converts an int slice to a float slice for the sparkline path
// helper. Aggregator returns []float64 already, but tests build []int.
func IntsToFloats(xs []int) []float64 {
	out := make([]float64, len(xs))
	for i, x := range xs {
		out[i] = float64(x)
	}
	return out
}

// ContainerRow joins one types.Container with the per-container aggregated
// stats so the table can be rendered from a flat list.
type ContainerRow struct {
	Container types.Container
	Stats     tap.ContainerStat
}

// JoinContainers returns one ContainerRow per registry entry, sorted by name.
// Containers without stats get an empty ContainerStat (Spark will be nil — the
// sparkline helper handles that path).
func JoinContainers(cs []types.Container, perContainer map[string]tap.ContainerStat) []ContainerRow {
	out := make([]ContainerRow, 0, len(cs))
	for _, c := range cs {
		key := c.Name
		if key == "" {
			key = ShortID(c.ID)
		}
		out = append(out, ContainerRow{Container: c, Stats: perContainer[key]})
	}
	// Manual insertion sort by name is fine for small lists. The dashboard
	// rarely tracks more than a few dozen containers.
	for i := 1; i < len(out); i++ {
		j := i
		for j > 0 && out[j-1].Container.Name > out[j].Container.Name {
			out[j-1], out[j] = out[j], out[j-1]
			j--
		}
	}
	return out
}

// ContainerLabel returns the display label for a flow event. Same logic as
// FlowRow's helper, exposed for the JoinContainers fallback when ContainerName
// is missing.
func ContainerLabel(name, id string, ifindex int) string {
	if name != "" {
		return name
	}
	if id != "" {
		return ShortID(id)
	}
	return fmt.Sprintf("if%d", ifindex)
}

// RangeBucketLabel returns the "last X · N buckets" subtitle the chart card
// shows next to its title, derived from the active range. Kept in lockstep
// with the bucket plan in app.js — change one, change both.
func RangeBucketLabel(r string) string {
	switch r {
	case "5m":
		return "last 5 min · 5s buckets"
	case "15m":
		return "last 15 min · 15s buckets"
	case "1h":
		return "last 1 hour · 1m buckets"
	case "6h":
		return "last 6 hours · 5m buckets"
	case "24h":
		return "last 24 hours · 15m buckets"
	default:
		return "last 1 hour · 1m buckets"
	}
}

// allRules returns the flat list of policy entries for one container — exact
// names first, then suffixes (preserving the dot-prefix), then port numbers.
// Used by the chip column in the containers table.
func allRules(c types.Container) []string {
	out := make([]string, 0, len(c.Policy.Exact)+len(c.Policy.Suffix)+len(c.Policy.Ports))
	out = append(out, c.Policy.Exact...)
	for _, s := range c.Policy.Suffix {
		out = append(out, "*."+strings.TrimPrefix(s, "."))
	}
	for _, p := range c.Policy.Ports {
		out = append(out, fmt.Sprintf(":%d", p))
	}
	return out
}
