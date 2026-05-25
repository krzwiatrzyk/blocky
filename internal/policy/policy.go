// Package policy compiles blocky's Docker labels into a normalized allow-list.
//
// Two labels are read:
//
//   - blocky.allowed-https-domains: comma-separated hostnames. Each entry is
//     either an exact hostname ("api.example.com") or a left-most wildcard
//     ("*.example.com"). Names are case-insensitive and lowercased on parse.
//   - blocky.allowed-ports: comma-separated TCP/UDP port numbers (decimal).
//     If set, traffic to any port outside the list is dropped. 53 and 443
//     must be included explicitly if the container needs them.
//
// Duplicates are removed (preserving first-seen order) so output is
// deterministic.
package policy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"blocky/internal/types"
)

// LabelKeyEnabled is the docker label that opts a container in to blocky
// management. Without it the container is ignored entirely — no BPF program
// is attached and the container does not appear in the dashboard.
//
// With `blocky.enabled=true` and no other blocky labels, the container runs
// in observe-only mode: BPF is attached, all traffic is allowed, every new
// flow surfaces in the UI for inspection.
const LabelKeyEnabled = "blocky.enabled"

// LabelKeyDomains is the docker label carrying the HTTPS SNI allow-list.
const LabelKeyDomains = "blocky.allowed-https-domains"

// LabelKeyPorts is the docker label carrying the destination-port allow-list.
const LabelKeyPorts = "blocky.allowed-ports"

// IsEnabled reports whether the given docker label value opts the container
// in to blocky management. Accepted positive values are "true", "1", "yes"
// (case-insensitive); everything else (including empty) means opted out.
func IsEnabled(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "true", "1", "yes", "on":
		return true
	}
	return false
}

// MaxHostLen is the longest hostname the BPF program can match. Bounded by the
// in-kernel stack buffer (NAME_BUF_LEN-1 = 31 bytes). Anything longer is
// rejected at parse time so the reconciler doesn't silently truncate.
const MaxHostLen = 31

// MaxRulesPerKind is the maximum number of exact and suffix host rules the
// BPF program can hold per container (independently). Mirrors the MAX_RULES
// define in blocky.c.
const MaxRulesPerKind = 16

// MaxPorts is the maximum number of ports the BPF program can hold per
// container. Mirrors the MAX_PORTS define in blocky.c.
const MaxPorts = 16

// ParseDomains compiles the blocky.allowed-https-domains label value into the
// Exact/Suffix fields of a Policy.
//
// maxPerKind bounds Exact and Suffix independently. The caller should pass the
// configured BLOCKY_MAX_RULES_PER_CONTAINER value.
func ParseDomains(label string, maxPerKind int) (types.Policy, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return types.Policy{}, nil
	}

	var (
		p          types.Policy
		seenExact  = map[string]struct{}{}
		seenSuffix = map[string]struct{}{}
	)

	for _, raw := range strings.Split(label, ",") {
		entry := strings.ToLower(strings.TrimSpace(raw))
		if entry == "" {
			continue
		}

		// Any '*' in the entry must be exactly the "*." prefix and nowhere else.
		isWildcard := false
		host := entry
		if strings.Contains(entry, "*") {
			if !strings.HasPrefix(entry, "*.") || strings.Contains(entry[2:], "*") {
				return types.Policy{}, fmt.Errorf("entry %q: wildcard must be exactly one '*.' prefix", raw)
			}
			isWildcard = true
			host = entry[2:]
		}

		if err := validateHostname(host); err != nil {
			return types.Policy{}, fmt.Errorf("entry %q: %w", raw, err)
		}

		if isWildcard {
			if _, dup := seenSuffix[host]; dup {
				continue
			}
			seenSuffix[host] = struct{}{}
			p.Suffix = append(p.Suffix, host)
			if len(p.Suffix) > maxPerKind {
				return types.Policy{}, fmt.Errorf("too many suffix rules (>%d)", maxPerKind)
			}
		} else {
			if _, dup := seenExact[host]; dup {
				continue
			}
			seenExact[host] = struct{}{}
			p.Exact = append(p.Exact, host)
			if len(p.Exact) > maxPerKind {
				return types.Policy{}, fmt.Errorf("too many exact rules (>%d)", maxPerKind)
			}
		}
	}
	return p, nil
}

// ParsePorts compiles the blocky.allowed-ports label value into a
// deduplicated, ordered list of uint16 ports.
//
// An empty/whitespace-only label returns nil, nil — the caller treats nil as
// "no port filter, apply legacy mode".
func ParsePorts(label string) ([]uint16, error) {
	label = strings.TrimSpace(label)
	if label == "" {
		return nil, nil
	}
	var (
		out  []uint16
		seen = map[uint16]struct{}{}
	)
	for _, raw := range strings.Split(label, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		n, err := strconv.Atoi(entry)
		if err != nil {
			return nil, fmt.Errorf("entry %q: %w", raw, err)
		}
		if n < 1 || n > 65535 {
			return nil, fmt.Errorf("entry %q: port out of range (1..65535)", raw)
		}
		port := uint16(n) //nolint:gosec // bounded above
		if _, dup := seen[port]; dup {
			continue
		}
		seen[port] = struct{}{}
		out = append(out, port)
		if len(out) > MaxPorts {
			return nil, fmt.Errorf("too many ports (>%d)", MaxPorts)
		}
	}
	return out, nil
}

// Matches reports whether host is allowed by the policy. Used in userspace tests and
// in the tap-client side; the kernel decision is in BPF, not here.
func Matches(p types.Policy, host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return false
	}
	for _, e := range p.Exact {
		if e == host {
			return true
		}
	}
	for _, s := range p.Suffix {
		if host == s || strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

func validateHostname(h string) error {
	if h == "" {
		return errors.New("invalid hostname: empty")
	}
	if len(h) > MaxHostLen {
		return fmt.Errorf("invalid hostname: longer than %d bytes (BPF stack-buffer limit)", MaxHostLen)
	}
	// Hostnames consist of labels separated by '.'. Each label: 1-63 chars,
	// [a-z0-9-], must not start or end with '-'. We allow underscores per
	// real-world DNS usage.
	for _, label := range strings.Split(h, ".") {
		if err := validateLabel(label); err != nil {
			return fmt.Errorf("invalid hostname: %w", err)
		}
	}
	return nil
}

func validateLabel(l string) error {
	if l == "" {
		return errors.New("empty label")
	}
	if len(l) > 63 {
		return errors.New("label longer than 63 chars")
	}
	if l[0] == '-' || l[len(l)-1] == '-' {
		return errors.New("label must not start or end with '-'")
	}
	for _, r := range l {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("invalid char %q", r)
		}
	}
	return nil
}
