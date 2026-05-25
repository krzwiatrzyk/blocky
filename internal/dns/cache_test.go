package dns_test

import (
	"strconv"
	"sync"
	"testing"

	"blocky/internal/dns"
)

func TestPutAndLookup(t *testing.T) {
	t.Parallel()
	c := dns.New(8)

	c.Put(1, "10.0.0.1", "foo.example.com")
	c.Put(1, "10.0.0.2", "bar.example.com")

	if got, ok := c.Lookup(1, "10.0.0.1"); !ok || got != "foo.example.com" {
		t.Errorf("Lookup(1, 10.0.0.1) = %q,%v, want foo.example.com,true", got, ok)
	}
	if got, ok := c.Lookup(1, "10.0.0.2"); !ok || got != "bar.example.com" {
		t.Errorf("Lookup(1, 10.0.0.2) = %q,%v, want bar.example.com,true", got, ok)
	}
}

func TestLookupMissReturnsFalse(t *testing.T) {
	t.Parallel()
	c := dns.New(4)
	if _, ok := c.Lookup(1, "10.0.0.99"); ok {
		t.Errorf("expected miss, got hit")
	}
}

func TestIsolationPerIfindex(t *testing.T) {
	t.Parallel()
	c := dns.New(4)
	c.Put(1, "10.0.0.1", "alice")
	c.Put(2, "10.0.0.1", "bob")

	if got, _ := c.Lookup(1, "10.0.0.1"); got != "alice" {
		t.Errorf("ifindex 1 lookup = %q, want alice", got)
	}
	if got, _ := c.Lookup(2, "10.0.0.1"); got != "bob" {
		t.Errorf("ifindex 2 lookup = %q, want bob", got)
	}
}

func TestPutUpdatesExistingName(t *testing.T) {
	t.Parallel()
	c := dns.New(4)
	c.Put(1, "1.2.3.4", "first.example")
	c.Put(1, "1.2.3.4", "second.example")
	if got, _ := c.Lookup(1, "1.2.3.4"); got != "second.example" {
		t.Errorf("after rewrite, got %q, want second.example", got)
	}
	if got := c.Size(1); got != 1 {
		t.Errorf("size after rewrite = %d, want 1 (no growth)", got)
	}
}

func TestLRUEvictsOldest(t *testing.T) {
	t.Parallel()
	c := dns.New(3)
	c.Put(1, "1.1.1.1", "a")
	c.Put(1, "2.2.2.2", "b")
	c.Put(1, "3.3.3.3", "c")
	c.Put(1, "4.4.4.4", "d") // should evict "1.1.1.1"

	if _, ok := c.Lookup(1, "1.1.1.1"); ok {
		t.Errorf("expected 1.1.1.1 to be evicted")
	}
	if _, ok := c.Lookup(1, "4.4.4.4"); !ok {
		t.Errorf("4.4.4.4 (newest) should be present")
	}
	if got := c.Size(1); got != 3 {
		t.Errorf("size = %d, want 3 (bound)", got)
	}
}

func TestPutMovesToFront(t *testing.T) {
	t.Parallel()
	c := dns.New(2)
	c.Put(1, "1.1.1.1", "a")
	c.Put(1, "2.2.2.2", "b")
	// Re-Put a: should move it to front. Now "b" is the oldest.
	c.Put(1, "1.1.1.1", "a")
	c.Put(1, "3.3.3.3", "c") // should evict b, not a

	if _, ok := c.Lookup(1, "2.2.2.2"); ok {
		t.Errorf("expected 2.2.2.2 to be evicted after re-put of 1.1.1.1")
	}
	if _, ok := c.Lookup(1, "1.1.1.1"); !ok {
		t.Errorf("1.1.1.1 should still be present after being refreshed")
	}
}

func TestForget(t *testing.T) {
	t.Parallel()
	c := dns.New(4)
	c.Put(1, "1.1.1.1", "a")
	c.Put(2, "2.2.2.2", "b")
	c.Forget(1)

	if _, ok := c.Lookup(1, "1.1.1.1"); ok {
		t.Errorf("entries for ifindex 1 should be gone after Forget")
	}
	if _, ok := c.Lookup(2, "2.2.2.2"); !ok {
		t.Errorf("Forget(1) should not affect ifindex 2")
	}
}

func TestPutDropsEmpty(t *testing.T) {
	t.Parallel()
	c := dns.New(4)
	c.Put(1, "", "name")
	c.Put(1, "1.1.1.1", "")
	if got := c.Size(1); got != 0 {
		t.Errorf("Put with empty fields should not record an entry, size=%d", got)
	}
}

func TestConcurrent(t *testing.T) {
	t.Parallel()
	c := dns.New(64)
	var wg sync.WaitGroup
	const workers = 8
	const ops = 200

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < ops; i++ {
				ip := "10.0." + strconv.Itoa(w) + "." + strconv.Itoa(i)
				c.Put(1, ip, "host-"+strconv.Itoa(i))
				_, _ = c.Lookup(1, ip)
			}
		}(w)
	}
	wg.Wait()
}
