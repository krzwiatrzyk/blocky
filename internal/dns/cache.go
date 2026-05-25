// Package dns holds a per-container IP→domain cache populated from observed
// DNS responses.
//
// The tap layer consumes DNSResolved events from the BPF response-side
// program and feeds them into this cache. When a subsequent flow event
// arrives without a parsed name (e.g. an outbound TCP/443 connection), the
// hub looks up the destination IP here and fills the Name field — answering
// "which domain did the container resolve this IP from?" without re-running
// any DNS logic in userspace.
//
// Per container means per ifindex: CDNs return different IPs to different
// clients, so a global cache would surface the wrong domain. The bound is
// enforced per container as well, so one chatty container can't evict
// another container's entries.
package dns

import (
	"container/list"
	"sync"
)

// Cache is the per-container IP→domain map. Safe for concurrent use.
type Cache struct {
	mu              sync.Mutex
	maxPerContainer int
	perContainer    map[int]*containerCache
}

// containerCache is a simple bounded LRU keyed by IP string.
type containerCache struct {
	order *list.List               // most-recently-touched at the front
	byIP  map[string]*list.Element // ip -> element holding *entry
}

type entry struct {
	ip   string
	name string
}

// New builds a Cache. maxPerContainer < 1 is treated as 1 to keep the LRU
// bookkeeping sane.
func New(maxPerContainer int) *Cache {
	if maxPerContainer < 1 {
		maxPerContainer = 1
	}
	return &Cache{
		maxPerContainer: maxPerContainer,
		perContainer:    map[int]*containerCache{},
	}
}

// Put records that ifindex resolved name → ip. If name is empty or ip is
// empty the entry is dropped. Existing entries are moved to the head of the
// LRU and their name is updated (later resolutions win).
func (c *Cache) Put(ifindex int, ip, name string) {
	if ip == "" || name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	cc, ok := c.perContainer[ifindex]
	if !ok {
		cc = &containerCache{
			order: list.New(),
			byIP:  map[string]*list.Element{},
		}
		c.perContainer[ifindex] = cc
	}

	if el, ok := cc.byIP[ip]; ok {
		el.Value.(*entry).name = name
		cc.order.MoveToFront(el)
		return
	}

	el := cc.order.PushFront(&entry{ip: ip, name: name})
	cc.byIP[ip] = el

	if cc.order.Len() > c.maxPerContainer {
		oldest := cc.order.Back()
		if oldest != nil {
			cc.order.Remove(oldest)
			delete(cc.byIP, oldest.Value.(*entry).ip)
		}
	}
}

// Lookup returns the most recent name associated with (ifindex, ip), or
// ("", false) if none. Lookups do not refresh the LRU position — the cache
// reflects what was resolved, not what was consulted.
func (c *Cache) Lookup(ifindex int, ip string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	cc, ok := c.perContainer[ifindex]
	if !ok {
		return "", false
	}
	el, ok := cc.byIP[ip]
	if !ok {
		return "", false
	}
	return el.Value.(*entry).name, true
}

// Forget drops the entire LRU for a container. Call when a container detaches
// so subsequent ifindex reuse doesn't leak stale mappings.
func (c *Cache) Forget(ifindex int) {
	c.mu.Lock()
	delete(c.perContainer, ifindex)
	c.mu.Unlock()
}

// Size returns the number of cached entries for a container (for tests).
func (c *Cache) Size(ifindex int) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cc, ok := c.perContainer[ifindex]
	if !ok {
		return 0
	}
	return cc.order.Len()
}

// Entry is one observed IP→name resolution surfaced by SnapshotAll.
type Entry struct {
	Ifindex int
	IP      string
	Name    string
}

// SnapshotAll returns every cached (ifindex, ip, name) entry in MRU order
// within each container, with no defined ordering across containers. The
// dashboard's DNS view renders this into the resolved-name cache table.
func (c *Cache) SnapshotAll() []Entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []Entry
	for ifindex, cc := range c.perContainer {
		for el := cc.order.Front(); el != nil; el = el.Next() {
			e := el.Value.(*entry)
			out = append(out, Entry{Ifindex: ifindex, IP: e.ip, Name: e.name})
		}
	}
	return out
}
