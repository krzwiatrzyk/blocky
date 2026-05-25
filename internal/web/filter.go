package web

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"blocky/internal/types"
)

// Filter is the per-WS-connection view restriction. The dashboard renders one
// row per FlowEvent that Matches reports true; everything else is dropped at
// the WS handler.
//
// All slice fields use OR semantics inside the field (any-of); fields combine
// with AND semantics across the struct.
//
// ExcludeDNS is a single-purpose negative filter: when true, UDP/53 events
// are dropped. The dashboard's recent-traffic table and chart use this so
// DNS shows up only on the dedicated /dns view (and in the dashboard's
// "DNS Queries" KPI, which is rendered server-side from a separate counter).
type Filter struct {
	Container  string // substring on container name (case-insensitive)
	Verdicts   []types.Verdict
	Protocols  []string // "tcp" / "udp"
	DstPorts   []uint16
	Name       string // substring on event Name (case-insensitive)
	Reasons    []types.Reason
	ExcludeDNS bool
}

// DefaultFilterFor returns the initial filter for a view.
//
//   - "dns"       — scope to UDP/53 only.
//   - "dashboard" — exclude UDP/53 so the overview KPIs and chart don't
//     drown in DNS-query noise; the dedicated DNS KPI is still rendered
//     server-side from a separate counter.
//   - everything else (including "traffic") — no filter; the user has the
//     Filters rail for explicit control.
func DefaultFilterFor(view string) Filter {
	switch view {
	case "dns":
		return Filter{Protocols: []string{"udp"}, DstPorts: []uint16{53}}
	case "dashboard":
		return Filter{ExcludeDNS: true}
	}
	return Filter{}
}

// Matches reports whether ev should be surfaced to this subscriber.
func (f *Filter) Matches(ev *types.FlowEvent) bool {
	if f.ExcludeDNS && ev.Protocol == "udp" && ev.DstPort == 53 {
		return false
	}
	if f.Container != "" && !containsFold(ev.ContainerName, f.Container) {
		return false
	}
	if len(f.Verdicts) > 0 && !slices.Contains(f.Verdicts, ev.Verdict) {
		return false
	}
	if len(f.Protocols) > 0 && !slices.Contains(f.Protocols, ev.Protocol) {
		return false
	}
	if len(f.DstPorts) > 0 && !slices.Contains(f.DstPorts, ev.DstPort) {
		return false
	}
	if f.Name != "" && !containsFold(ev.Name, f.Name) {
		return false
	}
	if len(f.Reasons) > 0 && !slices.Contains(f.Reasons, ev.Reason) {
		return false
	}
	return true
}

// ParseFilterMessage decodes a JSON object posted by the right-sidebar form
// via the htmx-ws extension. Unknown keys are ignored; bad ports are skipped
// rather than failing the message (the form may submit partial / typo input
// keystroke-by-keystroke).
func ParseFilterMessage(raw []byte) (Filter, error) {
	// htmx-ws posts {field:value, ..., "HEADERS":{...}} — values are strings,
	// arrays of strings for checkbox groups, or absent for blanks.
	var msg map[string]any
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Filter{}, err
	}
	f := Filter{
		Container: stringOf(msg["container"]),
		Verdicts:  verdictsOf(msg["verdict"]),
		Protocols: stringsOf(msg["protocol"]),
		DstPorts:  portsOf(msg["dport"]),
		Name:      stringOf(msg["name"]),
		Reasons:   reasonsOf(msg["reason"]),
	}
	return f, nil
}

func stringOf(v any) string {
	if s, ok := v.(string); ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func stringsOf(v any) []string {
	switch t := v.(type) {
	case string:
		if s := strings.TrimSpace(t); s != "" {
			return []string{s}
		}
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func verdictsOf(v any) []types.Verdict {
	xs := stringsOf(v)
	if len(xs) == 0 {
		return nil
	}
	out := make([]types.Verdict, 0, len(xs))
	for _, x := range xs {
		out = append(out, types.Verdict(strings.ToLower(x)))
	}
	return out
}

func reasonsOf(v any) []types.Reason {
	xs := stringsOf(v)
	if len(xs) == 0 {
		return nil
	}
	out := make([]types.Reason, 0, len(xs))
	for _, x := range xs {
		out = append(out, types.Reason(x))
	}
	return out
}

// portsOf parses a comma- or whitespace-separated list of ports from a string
// (the form input) or a JSON array of strings.
func portsOf(v any) []uint16 {
	xs := stringsOf(v)
	if len(xs) == 0 {
		return nil
	}
	var out []uint16
	for _, s := range xs {
		for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
			n, err := strconv.Atoi(tok)
			if err != nil || n <= 0 || n > 65535 {
				continue
			}
			out = append(out, uint16(n))
		}
	}
	return out
}

func containsFold(haystack, needle string) bool {
	return strings.Contains(strings.ToLower(haystack), strings.ToLower(needle))
}
