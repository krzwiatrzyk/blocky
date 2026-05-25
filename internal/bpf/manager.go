// Package bpf compiles, loads, and operates the blocky eBPF program.
package bpf

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"sync"

	"blocky/internal/policy"
	"blocky/internal/types"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/rs/zerolog"
)

const (
	modePass uint8 = 0
	modeDeny uint8 = 1
)

// attachedLinks holds both TCX attachments for a single veth. The egress
// program filters outbound packets; the response program observes inbound
// DNS responses for IP→domain learning.
type attachedLinks struct {
	egress   link.Link // host-side veth INGRESS (= container outbound)
	response link.Link // host-side veth EGRESS  (= container inbound)
}

// Manager owns the loaded BPF programs + maps and a registry of per-ifindex links.
type Manager struct {
	log   zerolog.Logger
	objs  blockyBPFObjects
	mu    sync.Mutex
	links map[int]attachedLinks // ifindex -> attached pair
	ports map[uint32][]uint16   // ifindex -> last-written port allowlist (for delta clear)

	events    chan types.FlowEvent
	resolved  chan DNSResolved
	reader    *ringbufReader
	resReader *dnsResolvedReader
}

// New loads the BPF program. Caller must Close() it on shutdown.
func New(log zerolog.Logger) (*Manager, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("remove memlock rlimit: %w", err)
	}
	var objs blockyBPFObjects
	if err := loadBlockyBPFObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	m := &Manager{
		log:      log,
		objs:     objs,
		links:    map[int]attachedLinks{},
		ports:    map[uint32][]uint16{},
		events:   make(chan types.FlowEvent, 1024),
		resolved: make(chan DNSResolved, 1024),
	}
	r, err := newRingbufReader(objs.Events, m.events, log)
	if err != nil {
		_ = objs.Close()
		return nil, fmt.Errorf("ringbuf reader: %w", err)
	}
	m.reader = r
	rr, err := newDNSResolvedReader(objs.DnsResolved, m.resolved, log)
	if err != nil {
		_ = r.Close()
		_ = objs.Close()
		return nil, fmt.Errorf("dns_resolved reader: %w", err)
	}
	m.resReader = rr
	return m, nil
}

// Events returns the receive side of the per-flow event channel.
func (m *Manager) Events() <-chan types.FlowEvent { return m.events }

// ResolvedNames returns the receive side of the DNS-response event channel —
// one item per A-record observed on UDP/53 responses to attached containers.
func (m *Manager) ResolvedNames() <-chan DNSResolved { return m.resolved }

// Close detaches all links, closes maps + program, and stops the ringbuf readers.
func (m *Manager) Close() error {
	m.mu.Lock()
	for ifx, al := range m.links {
		if err := al.egress.Close(); err != nil {
			m.log.Error().Err(err).Int("ifindex", ifx).Msg("egress detach failed during shutdown")
		}
		if err := al.response.Close(); err != nil {
			m.log.Error().Err(err).Int("ifindex", ifx).Msg("response detach failed during shutdown")
		}
	}
	m.links = map[int]attachedLinks{}
	m.mu.Unlock()

	var firstErr error
	if m.reader != nil {
		if err := m.reader.Close(); err != nil {
			firstErr = err
		}
	}
	if m.resReader != nil {
		if err := m.resReader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if err := m.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	close(m.events)
	close(m.resolved)
	return firstErr
}

// Attach attaches the BPF program to the host-side veth of ifindex and installs
// the per-container policy in the BPF maps. Idempotent: re-Attach updates rules.
func (m *Manager) Attach(ifindex int, p types.Policy) error {
	if ifindex <= 0 {
		return fmt.Errorf("bad ifindex %d", ifindex)
	}
	ifx, err := ifindexToU32(ifindex)
	if err != nil {
		return err
	}
	if perr := m.writePolicy(ifx, p); perr != nil {
		return fmt.Errorf("write policy ifindex=%d: %w", ifindex, perr)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, ok := m.links[ifindex]; ok {
		// Already attached; only the policy needed updating.
		return nil
	}

	// IMPORTANT: on a veth pair, the container's outbound traffic arrives at
	// the host-side peer as INGRESS (the host stack receives it). Attaching
	// the filter on egress here would catch packets going TO the container,
	// which is the opposite of what we want.
	egressLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   m.objs.BlockyEgress,
		Attach:    ebpf.AttachTCXIngress,
	})
	if err != nil {
		return fmt.Errorf("attach egress tcx ifindex=%d: %w", ifindex, err)
	}

	// The response program runs on the inverse direction — packets going TO
	// the container. That's where DNS responses arrive. It never drops or
	// rewrites; only observes UDP/53 to populate the userspace IP→domain cache.
	responseLink, err := link.AttachTCX(link.TCXOptions{
		Interface: ifindex,
		Program:   m.objs.BlockyResponse,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		_ = egressLink.Close()
		return fmt.Errorf("attach response tcx ifindex=%d: %w", ifindex, err)
	}

	m.links[ifindex] = attachedLinks{egress: egressLink, response: responseLink}
	return nil
}

// Detach removes both BPF programs from the veth and clears its map entries.
func (m *Manager) Detach(ifindex int) error {
	m.mu.Lock()
	al, ok := m.links[ifindex]
	delete(m.links, ifindex)
	m.mu.Unlock()
	if ok {
		var firstErr error
		if err := al.egress.Close(); err != nil {
			firstErr = fmt.Errorf("close egress link ifindex=%d: %w", ifindex, err)
		}
		if err := al.response.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close response link ifindex=%d: %w", ifindex, err)
		}
		if firstErr != nil {
			return firstErr
		}
	}
	ifx, err := ifindexToU32(ifindex)
	if err != nil {
		return err
	}
	return m.clearPolicy(ifx)
}

func ifindexToU32(ifindex int) (uint32, error) {
	if ifindex < 0 || ifindex > math.MaxUint32 {
		return 0, fmt.Errorf("ifindex %d out of uint32 range", ifindex)
	}
	return uint32(ifindex), nil
}

func (m *Manager) writePolicy(ifindex uint32, p types.Policy) error {
	if len(p.Exact) > policy.MaxRulesPerKind || len(p.Suffix) > policy.MaxRulesPerKind {
		return fmt.Errorf("too many rules: %d exact, %d suffix (max %d each)",
			len(p.Exact), len(p.Suffix), policy.MaxRulesPerKind)
	}
	if len(p.Ports) > policy.MaxPorts {
		return fmt.Errorf("too many ports: %d (max %d)", len(p.Ports), policy.MaxPorts)
	}

	// Snapshot the previously-written port list and reset the registry; the
	// new entries (below) reseat it. m.ports is touched only here and in
	// clearPolicy, and Attach/Detach are serialised by the reconciler — but
	// take the lock anyway so -race stays happy.
	m.mu.Lock()
	prevPorts := m.ports[ifindex]
	if len(p.Ports) == 0 {
		delete(m.ports, ifindex)
	} else {
		m.ports[ifindex] = slices.Clone(p.Ports)
	}
	m.mu.Unlock()

	// Clear previous entries first so shrinking policies don't leak ghosts.
	if err := m.clearPolicyRules(ifindex); err != nil {
		return err
	}
	if err := m.deletePortEntries(ifindex, prevPorts); err != nil {
		return err
	}

	for i, name := range p.Exact {
		k := blockyBPFRuleKeyT{Ifindex: ifindex, Idx: uint8(i)}
		v := buildRuleVal(name)
		if err := m.objs.PolicyExact.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("policy_exact[%d]: %w", i, err)
		}
	}
	for i, name := range p.Suffix {
		k := blockyBPFRuleKeyT{Ifindex: ifindex, Idx: uint8(i)}
		v := buildRuleVal(name)
		if err := m.objs.PolicySuffix.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("policy_suffix[%d]: %w", i, err)
		}
	}
	for _, port := range p.Ports {
		k := blockyBPFPortKeyT{Ifindex: ifindex, Port: port}
		v := uint8(1)
		if err := m.objs.PolicyPorts.Update(&k, &v, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("policy_ports[%d]: %w", port, err)
		}
	}

	mode := modeDeny
	if !p.IsActive() {
		// Defensive: an inactive policy shouldn't reach this path (reconciler
		// is supposed to skip containers that don't opt in via blocky.enabled),
		// but if it does, mode=MODE_PASS means the program early-exits.
		mode = modePass
	}
	observe := uint8(0)
	if p.Observe {
		observe = 1
	}
	// len(p.Exact) and len(p.Suffix) are bounded above by maxRules (16);
	// len(p.Ports) is bounded by maxPorts (16); the uint8 conversions below
	// are therefore safe.
	meta := blockyBPFPolicyMetaT{
		Mode:     mode,
		N_exact:  uint8(len(p.Exact)),  //nolint:gosec // bounded by maxRules
		N_suffix: uint8(len(p.Suffix)), //nolint:gosec // bounded by maxRules
		N_ports:  uint8(len(p.Ports)),  //nolint:gosec // bounded by maxPorts
		Observe:  observe,
	}
	if err := m.objs.PolicyMeta.Update(&ifindex, &meta, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("policy_meta: %w", err)
	}
	return nil
}

func (m *Manager) clearPolicy(ifindex uint32) error {
	m.mu.Lock()
	prevPorts := m.ports[ifindex]
	delete(m.ports, ifindex)
	m.mu.Unlock()

	if err := m.objs.PolicyMeta.Delete(&ifindex); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
		return fmt.Errorf("delete policy_meta: %w", err)
	}
	if err := m.clearPolicyRules(ifindex); err != nil {
		return err
	}
	return m.deletePortEntries(ifindex, prevPorts)
}

func (m *Manager) clearPolicyRules(ifindex uint32) error {
	for i := 0; i < policy.MaxRulesPerKind; i++ {
		k := blockyBPFRuleKeyT{Ifindex: ifindex, Idx: uint8(i)}
		if err := m.objs.PolicyExact.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete policy_exact[%d]: %w", i, err)
		}
		if err := m.objs.PolicySuffix.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete policy_suffix[%d]: %w", i, err)
		}
	}
	return nil
}

// deletePortEntries removes the explicitly-listed port keys from policy_ports.
// Caller must have already updated m.ports (so the slice passed in is the
// previous state, not the current one).
func (m *Manager) deletePortEntries(ifindex uint32, ports []uint16) error {
	for _, port := range ports {
		k := blockyBPFPortKeyT{Ifindex: ifindex, Port: port}
		if err := m.objs.PolicyPorts.Delete(&k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return fmt.Errorf("delete policy_ports[%d]: %w", port, err)
		}
	}
	return nil
}

func buildRuleVal(name string) blockyBPFRuleValT {
	var v blockyBPFRuleValT
	n := len(name)
	if n > len(v.Name) {
		n = len(v.Name)
	}
	// Name is [253]int8 in the generated bindings (signed char in C).
	// Cast byte-by-byte to keep the byte layout identical.
	for i := 0; i < n; i++ {
		v.Name[i] = int8(name[i]) //nolint:gosec // identity reinterpret
	}
	v.Len = uint16(n)
	return v
}
