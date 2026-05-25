package tap_test

import (
	"context"
	"testing"
	"time"

	"blocky/internal/bpf"
	"blocky/internal/dns"
	"blocky/internal/tap"
	"blocky/internal/types"
	"github.com/rs/zerolog"
)

type fakeRegistry struct {
	c  types.Container
	ok bool
}

func (f *fakeRegistry) LookupByIfindex(_ int) (types.Container, bool) {
	return f.c, f.ok
}

func TestHub_DecoratesAndBroadcasts(t *testing.T) {
	in := make(chan types.FlowEvent, 4)
	reg := &fakeRegistry{
		c:  types.Container{ID: "abc123", Name: "myctr"},
		ok: true,
	}
	h := tap.New(in, nil, nil, nil, reg, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{})
	defer h.Unsubscribe(s)

	in <- types.FlowEvent{Ifindex: 7, Verdict: types.VerdictAllow}

	select {
	case got := <-s.Channel():
		if got.ContainerID != "abc123" {
			t.Errorf("ContainerID = %q, want abc123", got.ContainerID)
		}
		if got.ContainerName != "myctr" {
			t.Errorf("ContainerName = %q, want myctr", got.ContainerName)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for event")
	}
}

func TestHub_FilterByVerdict(t *testing.T) {
	in := make(chan types.FlowEvent, 4)
	h := tap.New(in, nil, nil, nil, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{Verdict: types.VerdictDrop})
	defer h.Unsubscribe(s)

	in <- types.FlowEvent{Verdict: types.VerdictAllow}
	in <- types.FlowEvent{Verdict: types.VerdictDrop}

	select {
	case got := <-s.Channel():
		if got.Verdict != types.VerdictDrop {
			t.Errorf("got verdict %s, want drop (allow event leaked through filter)", got.Verdict)
		}
	case <-time.After(time.Second):
		t.Fatal("expected drop event")
	}

	select {
	case got := <-s.Channel():
		t.Fatalf("did not expect another event, got %+v", got)
	case <-time.After(50 * time.Millisecond):
	}
}

func TestHub_SlowConsumerDropsOldest(t *testing.T) {
	in := make(chan types.FlowEvent, 64)
	h := tap.New(in, nil, nil, nil, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{})
	defer h.Unsubscribe(s)

	// Pump way more than the buffer (256) and never read.
	for i := 0; i < 1000; i++ {
		in <- types.FlowEvent{Ifindex: i, Verdict: types.VerdictAllow}
	}

	// Give the hub time to drain `in`.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s.Dropped() > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("expected drops > 0, got %d", s.Dropped())
}

func TestHub_EnrichesNameFromDNSCache(t *testing.T) {
	in := make(chan types.FlowEvent, 4)
	resolved := make(chan bpf.DNSResolved, 4)
	cache := dns.New(8)
	h := tap.New(in, resolved, cache, nil, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{})
	defer h.Unsubscribe(s)

	// Feed a DNS resolution: ifindex=7, 1.2.3.4 → www.google.com.
	resolved <- bpf.DNSResolved{Ifindex: 7, IP: "1.2.3.4", Name: "www.google.com"}

	// Give the hub a moment to consume the resolved event before the flow event
	// arrives — the cache must be populated by the time decorate() runs.
	time.Sleep(50 * time.Millisecond)

	in <- types.FlowEvent{Ifindex: 7, DstIP: "1.2.3.4", Verdict: types.VerdictAllow}

	select {
	case got := <-s.Channel():
		if got.Name != "www.google.com" {
			t.Errorf("Name = %q, want www.google.com (enriched from cache)", got.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for enriched event")
	}
}

func TestHub_DoesNotOverwriteExistingName(t *testing.T) {
	in := make(chan types.FlowEvent, 4)
	cache := dns.New(8)
	cache.Put(7, "1.2.3.4", "different.example")
	h := tap.New(in, nil, cache, nil, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{})
	defer h.Unsubscribe(s)

	// Flow event already carries a Name (e.g., SNI). The hub must keep that.
	in <- types.FlowEvent{
		Ifindex: 7, DstIP: "1.2.3.4",
		Name:    "from-sni.example.com",
		Verdict: types.VerdictAllow,
	}

	select {
	case got := <-s.Channel():
		if got.Name != "from-sni.example.com" {
			t.Errorf("Name = %q, want from-sni.example.com (cache must not overwrite)", got.Name)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out")
	}
}

func TestHub_SubscribeWithSnapshot_ReplaysThenStreamsLive(t *testing.T) {
	in := make(chan types.FlowEvent, 8)
	fc := tap.NewFlowCache(16)
	h := tap.New(in, nil, nil, fc, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	// Pre-feed 3 events. Wait deterministically for the cache to settle by
	// polling Len — Run consumes from `in` on its own goroutine.
	for i := 1; i <= 3; i++ {
		in <- types.FlowEvent{Ifindex: i, Verdict: types.VerdictAllow}
	}
	deadline := time.Now().Add(2 * time.Second)
	for fc.Len() < 3 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if fc.Len() != 3 {
		t.Fatalf("flow cache Len = %d, want 3 (Run did not consume pre-fed events)", fc.Len())
	}

	sub, snap, maxSeq := h.SubscribeWithSnapshot(tap.SubscriberFilter{})
	defer h.Unsubscribe(sub)

	if len(snap) != 3 {
		t.Fatalf("snapshot len = %d, want 3", len(snap))
	}
	for i, ev := range snap {
		if want := uint64(i + 1); ev.Seq != want {
			t.Errorf("snap[%d].Seq = %d, want %d", i, ev.Seq, want)
		}
	}
	if maxSeq != 3 {
		t.Errorf("maxSeq = %d, want 3", maxSeq)
	}

	// Two live events arrive after subscription. They should reach sub.Channel
	// with Seq 4 and 5 (no duplicates of the snapshot, which had Seq 1-3).
	in <- types.FlowEvent{Ifindex: 4, Verdict: types.VerdictAllow}
	in <- types.FlowEvent{Ifindex: 5, Verdict: types.VerdictAllow}

	for _, want := range []uint64{4, 5} {
		select {
		case got := <-sub.Channel():
			if got.Seq != want {
				t.Errorf("live event Seq = %d, want %d", got.Seq, want)
			}
		case <-time.After(time.Second):
			t.Fatalf("timeout waiting for live event Seq=%d", want)
		}
	}
}

func TestHub_UnsubscribeClosesChannel(t *testing.T) {
	in := make(chan types.FlowEvent)
	h := tap.New(in, nil, nil, nil, &fakeRegistry{}, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.Run(ctx) }()

	s := h.Subscribe(tap.SubscriberFilter{})
	h.Unsubscribe(s)

	select {
	case _, ok := <-s.Channel():
		if ok {
			t.Fatal("expected channel to be closed")
		}
	case <-time.After(time.Second):
		t.Fatal("unsubscribe did not close the channel")
	}
}
