package tap

import (
	"sync"

	"blocky/internal/types"
)

// FlowCache is a bounded FIFO ring of the most recent decorated flow events.
// It exists so a new dashboard WS connection can replay recent history rather
// than starting from an empty table. Add and Snapshot are O(1) and O(n)
// respectively. Snapshot returns a copy in oldest→newest order so the caller
// can replay it directly to a subscriber. Capacity is configured via
// BLOCKY_FLOW_CACHE_SIZE.
type FlowCache struct {
	mu   sync.Mutex
	buf  []types.FlowEvent
	head int // index of next write slot
	n    int // current count, ≤ cap(buf)
}

// NewFlowCache returns a cache that holds the most recent size events. size
// values below 1 are clamped to 1 so a misconfigured env var can't panic.
func NewFlowCache(size int) *FlowCache {
	if size < 1 {
		size = 1
	}
	return &FlowCache{buf: make([]types.FlowEvent, size)}
}

// Add records ev. When the cache is full, the oldest event is overwritten.
func (c *FlowCache) Add(ev types.FlowEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf[c.head] = ev
	c.head = (c.head + 1) % len(c.buf)
	if c.n < len(c.buf) {
		c.n++
	}
}

// Snapshot returns the cached events in arrival order (oldest first). The
// returned slice is a fresh copy — safe for the caller to retain and iterate
// without holding the cache lock.
func (c *FlowCache) Snapshot() []types.FlowEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == 0 {
		return nil
	}
	out := make([]types.FlowEvent, c.n)
	start := (c.head - c.n + len(c.buf)) % len(c.buf)
	for i := 0; i < c.n; i++ {
		out[i] = c.buf[(start+i)%len(c.buf)]
	}
	return out
}

// Len returns the current number of cached events.
func (c *FlowCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}
