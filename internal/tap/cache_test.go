package tap_test

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"blocky/internal/tap"
	"blocky/internal/types"
)

func mkFlow(seq uint64) types.FlowEvent {
	return types.FlowEvent{
		Seq:       seq,
		Timestamp: time.Unix(int64(seq), 0),
		Ifindex:   int(seq),
		DstIP:     "1.2.3.4",
		Verdict:   types.VerdictAllow,
	}
}

func TestFlowCache_AddSnapshotOrder(t *testing.T) {
	c := tap.NewFlowCache(5)
	c.Add(mkFlow(1))
	c.Add(mkFlow(2))
	c.Add(mkFlow(3))

	got := c.Snapshot()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	for i, ev := range got {
		want := uint64(i + 1)
		if ev.Seq != want {
			t.Errorf("got[%d].Seq = %d, want %d (snapshot must be oldest-first)", i, ev.Seq, want)
		}
	}
}

func TestFlowCache_Eviction(t *testing.T) {
	c := tap.NewFlowCache(3)
	for i := 1; i <= 4; i++ {
		c.Add(mkFlow(uint64(i)))
	}
	got := c.Snapshot()
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (cap)", len(got))
	}
	wantSeqs := []uint64{2, 3, 4}
	for i, ev := range got {
		if ev.Seq != wantSeqs[i] {
			t.Errorf("got[%d].Seq = %d, want %d (oldest evicted)", i, ev.Seq, wantSeqs[i])
		}
	}
}

func TestFlowCache_LenTracksCount(t *testing.T) {
	c := tap.NewFlowCache(3)
	if c.Len() != 0 {
		t.Errorf("empty Len = %d, want 0", c.Len())
	}
	c.Add(mkFlow(1))
	if c.Len() != 1 {
		t.Errorf("after 1 add Len = %d, want 1", c.Len())
	}
	c.Add(mkFlow(2))
	c.Add(mkFlow(3))
	c.Add(mkFlow(4)) // evicts 1
	if c.Len() != 3 {
		t.Errorf("after overflow Len = %d, want 3 (cap)", c.Len())
	}
}

func TestFlowCache_ZeroOrNegativeSizeIsOne(t *testing.T) {
	for _, size := range []int{-1, 0} {
		c := tap.NewFlowCache(size)
		c.Add(mkFlow(1))
		c.Add(mkFlow(2))
		if got := c.Len(); got != 1 {
			t.Errorf("size=%d: Len after 2 adds = %d, want 1 (clamped to 1)", size, got)
		}
		snap := c.Snapshot()
		if len(snap) != 1 || snap[0].Seq != 2 {
			t.Errorf("size=%d: snapshot=%v, want [seq=2]", size, snap)
		}
	}
}

func TestFlowCache_SnapshotIsACopy(t *testing.T) {
	c := tap.NewFlowCache(5)
	c.Add(mkFlow(1))
	snap := c.Snapshot()
	c.Add(mkFlow(2))
	if len(snap) != 1 {
		t.Errorf("captured snapshot mutated: len = %d, want 1", len(snap))
	}
}

func TestFlowCache_ConcurrentAddSnapshot(t *testing.T) {
	const writers = 8
	const perWriter = 1000
	c := tap.NewFlowCache(256)
	var seq atomic.Uint64
	var snapshots atomic.Uint64

	var writersWG sync.WaitGroup
	for i := 0; i < writers; i++ {
		writersWG.Add(1)
		go func() {
			defer writersWG.Done()
			for j := 0; j < perWriter; j++ {
				c.Add(mkFlow(seq.Add(1)))
			}
		}()
	}

	// Readers run until writers all finish, observing many in-flight states.
	stop := make(chan struct{})
	var readersWG sync.WaitGroup
	for i := 0; i < 2; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				snap := c.Snapshot()
				if len(snap) > 256 {
					t.Errorf("snapshot len %d > cap 256", len(snap))
					return
				}
				snapshots.Add(1)
			}
		}()
	}

	writersWG.Wait()
	close(stop)
	readersWG.Wait()

	if got := c.Len(); got != 256 {
		t.Errorf("final Len = %d, want 256 (cap)", got)
	}
	if snapshots.Load() == 0 {
		t.Errorf("no snapshots taken — race conditions may have been hidden")
	}
}
