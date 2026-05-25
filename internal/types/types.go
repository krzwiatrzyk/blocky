// Package types holds value types shared across blocky packages.
//
// Kept dependency-free to avoid import cycles between bpf, reconciler, tap, and api.
package types

import "time"

// Verdict is the outcome of the BPF program for a single flow.
type Verdict string

// Verdict values.
const (
	VerdictAllow Verdict = "allow"
	VerdictDrop  Verdict = "drop"
)

// Reason names the rule that produced the verdict. Stable strings — clients filter on them.
type Reason string

// Reason values mirror the BPF program's REASON_* constants.
const (
	ReasonNoPolicy         Reason = "no-policy"
	ReasonDNSExempt        Reason = "dns-exempt"
	ReasonSNIAllowed       Reason = "sni-allowed"
	ReasonSNIBlocked       Reason = "sni-blocked"
	ReasonNonTLSRestricted Reason = "non-tls-restricted"
	ReasonTLSParseFailed   Reason = "tls-parse-failed"
	ReasonCTAllowed        Reason = "ct-allowed"
	ReasonCTDenied         Reason = "ct-denied"
	ReasonPortAllowed      Reason = "port-allowed"
	ReasonPortBlocked      Reason = "port-blocked"
)

// Policy is the compiled allowlist for one container.
//
// Exact and Suffix come from blocky.allowed-https-domains and drive the TLS-SNI
// matcher on tcp/443. Ports comes from blocky.allowed-ports and gates traffic
// at L4 before the SNI matcher runs. A non-empty Ports list switches the BPF
// program out of "legacy" mode where DNS and tcp/443 are hard-coded — every
// allowed port must then be listed explicitly, including 53 and 443.
//
// Observe (set when the container opts in via blocky.enabled=true but
// supplies no other policy labels) flips the BPF program to observe-only:
// every drop becomes an allow, but the per-flow event is still emitted so
// the operator can inspect what the container does in the dashboard.
type Policy struct {
	Exact   []string `json:"exact"`
	Suffix  []string `json:"suffix"`
	Ports   []uint16 `json:"ports,omitempty"`
	Observe bool     `json:"observe,omitempty"`
}

// HasRules reports whether the policy has any allow entries (Exact/Suffix/
// Ports). Observe-only policies return false here.
func (p Policy) HasRules() bool {
	return len(p.Exact)+len(p.Suffix)+len(p.Ports) > 0
}

// IsActive reports whether the BPF program should be attached for this
// policy: true when there's a rule list or when the container is in
// observe-only mode.
func (p Policy) IsActive() bool {
	return p.HasRules() || p.Observe
}

// Container is the registry view of a managed container.
type Container struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Image     string    `json:"image,omitempty"`
	HasPolicy bool      `json:"has_policy"`
	Policy    Policy    `json:"policy"`
	Ifindex   int       `json:"ifindex"`
	Status    string    `json:"status"` // active|failed|skipped
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// FlowEvent is one row in the live tap stream.
//
// Seq is assigned by the tap hub in monotonic order as it consumes events from
// the BPF manager. It lets WS replay subscribers de-dup events they already
// received via the historical snapshot. Zero on events that haven't yet passed
// through the hub.
type FlowEvent struct {
	Seq           uint64    `json:"seq,omitempty"`
	Timestamp     time.Time `json:"ts"`
	ContainerID   string    `json:"container_id"`
	ContainerName string    `json:"container_name"`
	Ifindex       int       `json:"ifindex"`
	SrcIP         string    `json:"src_ip"`
	SrcPort       uint16    `json:"src_port"`
	DstIP         string    `json:"dst_ip"`
	DstPort       uint16    `json:"dst_port"`
	Protocol      string    `json:"protocol"` // tcp|udp
	Name          string    `json:"name,omitempty"`
	Verdict       Verdict   `json:"verdict"`
	Reason        Reason    `json:"reason"`
}
