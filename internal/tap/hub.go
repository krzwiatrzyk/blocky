// Package tap implements per-flow event fan-out to WebSocket subscribers.
//
// A single Hub goroutine receives events from the BPF manager, decorates them
// with container metadata via a Registry, and forwards them to N subscribers.
// Each subscriber has a bounded send channel; on overflow the oldest event is
// dropped so a slow consumer cannot stall the pipeline.
package tap

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"blocky/internal/bpf"
	"blocky/internal/dns"
	"blocky/internal/types"
	"github.com/rs/zerolog"
)

// Registry resolves a veth ifindex to the container that owns it. Implemented
// by the reconciler.
type Registry interface {
	LookupByIfindex(ifindex int) (types.Container, bool)
}

// SubscriberFilter restricts which events a single subscriber receives.
type SubscriberFilter struct {
	Container string        // matches container ID prefix or exact name; empty = all
	Verdict   types.Verdict // "" = all
}

// Subscriber holds the channel a WS handler writes to its client.
type Subscriber struct {
	id      uint64
	filter  SubscriberFilter
	ch      chan types.FlowEvent
	dropped atomic.Uint64
}

// Channel returns the read side of the subscriber's event queue.
func (s *Subscriber) Channel() <-chan types.FlowEvent { return s.ch }

// Dropped returns the number of events the hub had to drop for this subscriber.
func (s *Subscriber) Dropped() uint64 { return s.dropped.Load() }

// Hub fans out decorated events to subscribers.
type Hub struct {
	in        <-chan types.FlowEvent
	resolved  <-chan bpf.DNSResolved
	cache     *dns.Cache
	flowCache *FlowCache
	registry  Registry
	log       zerolog.Logger
	bufSize   int

	mu          sync.RWMutex // also guards seqCounter so SubscribeWithSnapshot can capture an atomic prefix
	subscribers map[uint64]*Subscriber
	nextID      uint64
	seqCounter  uint64
}

// New builds a Hub. resolved, cache, and flowCache may all be nil; tests that
// only exercise fan-out can pass nil for the optional collaborators. In
// production, the daemon supplies all four.
func New(in <-chan types.FlowEvent, resolved <-chan bpf.DNSResolved, cache *dns.Cache,
	flowCache *FlowCache, registry Registry, log zerolog.Logger) *Hub {
	return &Hub{
		in:          in,
		resolved:    resolved,
		cache:       cache,
		flowCache:   flowCache,
		registry:    registry,
		log:         log,
		bufSize:     256,
		subscribers: map[uint64]*Subscriber{},
	}
}

// Subscribe registers a new subscriber. Caller must Unsubscribe when done.
func (h *Hub) Subscribe(f SubscriberFilter) *Subscriber {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.subscribeLocked(f)
}

func (h *Hub) subscribeLocked(f SubscriberFilter) *Subscriber {
	h.nextID++
	s := &Subscriber{
		id:     h.nextID,
		filter: f,
		ch:     make(chan types.FlowEvent, h.bufSize),
	}
	h.subscribers[s.id] = s
	return s
}

// SubscribeWithSnapshot atomically captures the current flow-cache contents
// and registers a new subscriber. Because Run takes the write lock when it
// publishes a new event (see broadcastLocked), no Add / broadcast can happen
// during this call — the returned snapshot is therefore a strict prefix of
// what the new subscriber will see live, and snapshotMaxSeq is the highest
// Seq in the snapshot (zero if empty).
//
// Callers should iterate snapshot first, then read from the subscriber's
// channel, skipping any event whose Seq ≤ snapshotMaxSeq for defence in depth.
// flowCache may be nil — the snapshot will be empty.
func (h *Hub) SubscribeWithSnapshot(f SubscriberFilter) (sub *Subscriber, snapshot []types.FlowEvent, snapshotMaxSeq uint64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	sub = h.subscribeLocked(f)
	if h.flowCache != nil {
		snapshot = h.flowCache.Snapshot()
		if n := len(snapshot); n > 0 {
			snapshotMaxSeq = snapshot[n-1].Seq
		}
	}
	return sub, snapshot, snapshotMaxSeq
}

// Unsubscribe removes a subscriber and closes its channel.
func (h *Hub) Unsubscribe(s *Subscriber) {
	h.mu.Lock()
	if _, ok := h.subscribers[s.id]; ok {
		delete(h.subscribers, s.id)
		close(s.ch)
	}
	h.mu.Unlock()
}

// Run blocks until ctx is canceled or the input channel closes.
func (h *Hub) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			h.closeAll()
			return nil
		case ev, ok := <-h.in:
			if !ok {
				h.closeAll()
				return nil
			}
			h.decorate(&ev)
			h.publish(ev)
		case r, ok := <-h.resolved:
			if !ok {
				// Closed dns_resolved channel just disables enrichment;
				// flow events still flow. Re-nil so the select doesn't spin.
				h.resolved = nil
				continue
			}
			if h.cache != nil {
				h.cache.Put(r.Ifindex, r.IP, r.Name)
			}
		}
	}
}

// publish assigns the next Seq, records the event in the flow cache, and fans
// it out to subscribers. The whole tuple runs under the hub's write lock so
// SubscribeWithSnapshot sees a consistent (cache, live-stream) cut: while it
// holds the lock no new Seq can be assigned and no broadcast can leak ahead
// of the snapshot it captures.
func (h *Hub) publish(ev types.FlowEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seqCounter++
	ev.Seq = h.seqCounter
	if h.flowCache != nil {
		h.flowCache.Add(ev)
	}
	h.broadcastLocked(ev)
}

func (h *Hub) decorate(ev *types.FlowEvent) {
	if h.registry != nil {
		if c, ok := h.registry.LookupByIfindex(ev.Ifindex); ok {
			ev.ContainerID = c.ID
			ev.ContainerName = c.Name
		}
	}
	// IP→domain enrichment: if the kernel didn't put a name in this event
	// (e.g. PORT_ALLOWED on a plain TCP/443 flow), see whether the container
	// previously resolved this destination via DNS.
	if ev.Name == "" && h.cache != nil {
		if name, ok := h.cache.Lookup(ev.Ifindex, ev.DstIP); ok {
			ev.Name = name
		}
	}
}

// broadcastLocked iterates subscribers and forwards ev to each one whose
// filter matches. The caller MUST hold h.mu (write lock) — Run reaches this
// via publish, which serializes Seq assignment, cache Add, and the fan-out
// loop together. All per-subscriber sends/recvs below use select-default so
// they never block while the lock is held.
func (h *Hub) broadcastLocked(ev types.FlowEvent) {
	for _, s := range h.subscribers {
		if !filterAllows(s.filter, &ev) {
			continue
		}
		select {
		case s.ch <- ev:
		default:
			// Drop oldest, push newest. Keeps newest events flowing.
			select {
			case <-s.ch:
			default:
			}
			select {
			case s.ch <- ev:
			default:
			}
			s.dropped.Add(1)
		}
	}
}

func filterAllows(f SubscriberFilter, ev *types.FlowEvent) bool {
	if f.Verdict != "" && f.Verdict != ev.Verdict {
		return false
	}
	if f.Container != "" {
		if !strings.HasPrefix(ev.ContainerID, f.Container) && ev.ContainerName != f.Container {
			return false
		}
	}
	return true
}

func (h *Hub) closeAll() {
	h.mu.Lock()
	for id, s := range h.subscribers {
		close(s.ch)
		delete(h.subscribers, id)
	}
	h.mu.Unlock()
}
