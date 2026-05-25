package tap

import (
	"sort"
	"time"

	"blocky/internal/types"
)

// SparkBuckets is the number of buckets emitted per sparkline series.
const SparkBuckets = 24

// KpiTotals summarises flow counts over a window.
type KpiTotals struct {
	Total      int
	Allow      int
	Block      int
	DNS        int
	AllowSpark []float64
	BlockSpark []float64
	DNSSpark   []float64
}

// DestStat is one row in the Top destinations panel.
type DestStat struct {
	Name  string
	Count int
	Allow int
	Block int
}

// ContainerStat aggregates flow events by container.
type ContainerStat struct {
	Allow int
	Block int
	Spark []float64
}

// Aggregate is the snapshot the dashboard reads. All fields cover the same
// fixed window (currently 1h hard-coded).
type Aggregate struct {
	Window       time.Duration
	Now          time.Time
	Totals       KpiTotals
	TopDest      []DestStat
	PerContainer map[string]ContainerStat
	RecentDNS    []types.FlowEvent
}

// AggregateOptions tunes Aggregate. TopN caps the destinations list. Zero
// values fall back to sensible defaults.
//
// ExcludeDNS controls whether UDP/53 events count toward Total, Allow,
// Block, the sparklines, top destinations, and per-container stats. The
// dedicated DNS counters (Totals.DNS, Totals.DNSSpark, RecentDNS) are
// unaffected — the dashboard's "DNS Queries" KPI still sees them even when
// ExcludeDNS is set, while the other tiles surface only non-DNS traffic.
type AggregateOptions struct {
	Window     time.Duration
	TopN       int
	ExcludeDNS bool
}

// Aggregate walks the FlowCache and returns counts, top destinations, and
// per-container stats over the requested window. Callers should treat the
// result as read-only.
func (h *Hub) Aggregate(opts AggregateOptions) Aggregate {
	if opts.Window <= 0 {
		opts.Window = time.Hour
	}
	if opts.TopN <= 0 {
		opts.TopN = 8
	}
	now := time.Now()
	a := Aggregate{
		Window:       opts.Window,
		Now:          now,
		PerContainer: map[string]ContainerStat{},
	}
	a.Totals.AllowSpark = make([]float64, SparkBuckets)
	a.Totals.BlockSpark = make([]float64, SparkBuckets)
	a.Totals.DNSSpark = make([]float64, SparkBuckets)

	if h.flowCache == nil {
		return a
	}
	events := h.flowCache.Snapshot()
	cutoff := now.Add(-opts.Window)
	bucketSize := opts.Window / time.Duration(SparkBuckets)
	if bucketSize <= 0 {
		bucketSize = time.Second
	}

	destByName := map[string]*DestStat{}
	perContainerSpark := map[string][]float64{}
	recentDNS := make([]types.FlowEvent, 0, 32)

	for _, ev := range events {
		if ev.Timestamp.Before(cutoff) {
			continue
		}
		idx := int(ev.Timestamp.Sub(cutoff) / bucketSize)
		if idx < 0 {
			idx = 0
		} else if idx >= SparkBuckets {
			idx = SparkBuckets - 1
		}

		isDNS := ev.Protocol == "udp" && ev.DstPort == 53

		// DNS-specific counters are always populated so the dashboard's
		// dedicated DNS Queries tile / recent-DNS panel keep working even
		// when ExcludeDNS is set.
		if isDNS {
			a.Totals.DNS++
			a.Totals.DNSSpark[idx]++
			if len(recentDNS) < cap(recentDNS) {
				recentDNS = append(recentDNS, ev)
			}
		}

		// Everything else (totals, sparks, destinations, per-container
		// stats) skips DNS when the caller asked for it — they're surfaced
		// only on the dedicated DNS view.
		if isDNS && opts.ExcludeDNS {
			continue
		}

		a.Totals.Total++
		switch ev.Verdict {
		case types.VerdictAllow:
			a.Totals.Allow++
			a.Totals.AllowSpark[idx]++
		case types.VerdictDrop:
			a.Totals.Block++
			a.Totals.BlockSpark[idx]++
		}

		if ev.Name != "" {
			d := destByName[ev.Name]
			if d == nil {
				d = &DestStat{Name: ev.Name}
				destByName[ev.Name] = d
			}
			d.Count++
			if ev.Verdict == types.VerdictAllow {
				d.Allow++
			} else {
				d.Block++
			}
		}

		key := containerKey(ev)
		cs := a.PerContainer[key]
		spark := perContainerSpark[key]
		if spark == nil {
			spark = make([]float64, SparkBuckets)
			perContainerSpark[key] = spark
		}
		spark[idx]++
		if ev.Verdict == types.VerdictAllow {
			cs.Allow++
		} else if ev.Verdict == types.VerdictDrop {
			cs.Block++
		}
		a.PerContainer[key] = cs
	}

	// Attach sparks now that maps are populated.
	for k, cs := range a.PerContainer {
		cs.Spark = perContainerSpark[k]
		a.PerContainer[k] = cs
	}

	// Top destinations: sort by count desc, then name asc for determinism.
	dests := make([]DestStat, 0, len(destByName))
	for _, d := range destByName {
		dests = append(dests, *d)
	}
	sort.Slice(dests, func(i, j int) bool {
		if dests[i].Count != dests[j].Count {
			return dests[i].Count > dests[j].Count
		}
		return dests[i].Name < dests[j].Name
	})
	if len(dests) > opts.TopN {
		dests = dests[:opts.TopN]
	}
	a.TopDest = dests

	// Recent DNS — newest first, cap to 10.
	sort.Slice(recentDNS, func(i, j int) bool {
		return recentDNS[i].Timestamp.After(recentDNS[j].Timestamp)
	})
	if len(recentDNS) > 10 {
		recentDNS = recentDNS[:10]
	}
	a.RecentDNS = recentDNS

	return a
}

// containerKey picks a stable identifier per container for aggregation. Name
// is preferred (matches the WS row's data-container attribute); short ID is
// the fallback so containers without a registry hit still aggregate.
func containerKey(ev types.FlowEvent) string {
	if ev.ContainerName != "" {
		return ev.ContainerName
	}
	if len(ev.ContainerID) >= 12 {
		return ev.ContainerID[:12]
	}
	if ev.ContainerID != "" {
		return ev.ContainerID
	}
	return ""
}
