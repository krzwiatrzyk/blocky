// blocky dashboard chart aggregator + small UI helpers.
//
// The server pushes one <tr> per flow event over WS; the row carries
// data-ts (ms), data-container, data-verdict attributes that this script
// reads to update a 60-bucket × 5s sliding window powering a uPlot bar chart.
//
// No bundler — this file is served directly from go:embed and the page already
// includes uPlot via CDN. Pure ES2017 to stay readable.

// ── Theme toggle ──────────────────────────────────────────────────────────
// Sidebar/header buttons call window.__blockyToggleTheme(). The initial value
// is set in layout.templ's pre-paint script so we never get a flash.
window.__blockyToggleTheme = function () {
    var root = document.documentElement;
    var next = root.dataset.theme === 'light' ? 'dark' : 'light';
    if (next === 'dark') {
        delete root.dataset.theme;
    } else {
        root.dataset.theme = 'light';
    }
    try { localStorage.setItem('blocky-theme', next); } catch (e) {}
};

// ── Recent traffic: pause/resume row prepending ───────────────────────────
// When paused, intercept incoming OOB-swapped <tr> elements and discard them
// before HTMX reaches its swap step. Toggle via the LIVE/PAUSE button.
window.__blockyTogglePause = function () {
    window.__blockyPaused = !window.__blockyPaused;
    var btn = document.getElementById('flow-pause');
    if (btn) {
        btn.textContent = window.__blockyPaused ? 'RESUME' : 'PAUSE';
        btn.classList.toggle('is-active', window.__blockyPaused);
    }
};
document.addEventListener('htmx:beforeSwap', function (e) {
    if (!window.__blockyPaused) return;
    // Drop only flow-row swaps; everything else (overview poll, dns cache) keeps swapping.
    var t = e.detail && e.detail.target;
    if (t && (t.id === 'flow-rows' || (t.closest && t.closest('#flow-rows')))) {
        e.preventDefault();
    }
});

(function () {
    'use strict';

    // Bucket plan per time range. Total window ≈ BUCKETS × BUCKET_MS.
    // Picked so each range has ~60–96 buckets — enough resolution to see
    // shape without producing a noisy chart.
    const RANGE_PLAN = {
        '5m':  { buckets: 60, bucketMs: 5 * 1000 },
        '15m': { buckets: 60, bucketMs: 15 * 1000 },
        '1h':  { buckets: 60, bucketMs: 60 * 1000 },
        '6h':  { buckets: 72, bucketMs: 5 * 60 * 1000 },
        '24h': { buckets: 96, bucketMs: 15 * 60 * 1000 },
    };
    const DEFAULT_RANGE = '5m';

    let BUCKETS = 60;
    let BUCKET_MS = 5000;
    const MAX_ROWS = 500;

    // Vertical room uPlot's legend (swatch + label table) consumes below the
    // canvas. The mount div is sized to chart-canvas + legend; the canvas
    // height we pass to uPlot subtracts this so the legend stays visible
    // inside the card's clipping region.
    const LEGEND_HEIGHT = 36;
    function chartCanvasHeight(mount) {
        return Math.max(80, mount.clientHeight - LEGEND_HEIGHT);
    }

    function getVar(name, fallback) {
        const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return v || fallback;
    }

    // bucket[i] is a map of group-key -> count, ordered oldest..newest
    let buckets = newBuckets();
    // Series colours; cycled through as new groups appear.
    const PALETTE = [
        '#38bdf8', '#fbbf24', '#a78bfa', '#34d399', '#f472b6',
        '#fb7185', '#60a5fa', '#facc15', '#4ade80', '#c084fc',
    ];
    const groupColour = new Map();

    function newBuckets() {
        const b = new Array(BUCKETS);
        for (let i = 0; i < BUCKETS; i++) b[i] = new Map();
        return b;
    }

    // When grouping by verdict, the two series have meaningful colours that
    // match the rest of the UI (allow = green, drop = red). Container groups
    // still cycle through PALETTE so each container gets a distinct hue.
    function pickColour(group) {
        if (!groupColour.has(group)) {
            if (group === 'allow') {
                groupColour.set(group, getVar('--allow-2', '#22c55e'));
            } else if (group === 'drop') {
                groupColour.set(group, getVar('--block', '#f87171'));
            } else {
                groupColour.set(group, PALETTE[groupColour.size % PALETTE.length]);
            }
        }
        return groupColour.get(group);
    }

    // chart state, lazy-initialised when the DOM mount point appears.
    let chart = null;
    let chartView = 'traffic';

    function init() {
        const mount = document.getElementById('chart');
        if (!mount) return; // not on a chart page
        chartView = mount.dataset.view || 'traffic';

        const range = mount.dataset.range && RANGE_PLAN[mount.dataset.range]
            ? mount.dataset.range
            : DEFAULT_RANGE;
        BUCKETS = RANGE_PLAN[range].buckets;
        BUCKET_MS = RANGE_PLAN[range].bucketMs;
        buckets = newBuckets();
        anchorBucketStart = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;

        chart = new uPlot({
            width: mount.clientWidth,
            height: chartCanvasHeight(mount),
            scales: { x: { time: true } },
            axes: [
                { stroke: getVar('--text-muted', '#94a3b8'), grid: { stroke: getVar('--border', '#1e293b') } },
                { stroke: getVar('--text-muted', '#94a3b8'), grid: { stroke: getVar('--border', '#1e293b') } },
            ],
            legend: { show: true },
            series: [
                { label: 'time' },
            ],
            cursor: { drag: { x: false, y: false } },
        }, emptyData(), mount);

        // Watch for new flow rows; each carries chart data in data- attributes.
        const tbody = document.getElementById('flow-rows');
        if (tbody) {
            new MutationObserver(onRowsAdded).observe(tbody, { childList: true });
        }

        // Group selector: re-bucket existing rows under the new key so the
        // chart keeps the data already on screen instead of resetting to
        // empty. New rows arriving over WS continue to land in their
        // matching buckets via onRowsAdded.
        const sel = document.getElementById('chart-group');
        if (sel) sel.addEventListener('change', () => {
            buckets = newBuckets();
            groupColour.clear();
            rebucketFromDOM();
            redraw();
        });

        // Drive bucket shift + redraw at 1Hz so empty seconds still render.
        setInterval(redraw, 1000);

        // Cap table size — drop oldest (bottom) rows.
        if (tbody) new MutationObserver(() => trimTable(tbody)).observe(tbody, { childList: true });

        window.addEventListener('resize', () => {
            chart.setSize({ width: mount.clientWidth, height: chartCanvasHeight(mount) });
        });
    }

    function groupKey(row) {
        const sel = document.getElementById('chart-group');
        const mode = sel ? sel.value : 'container';
        if (mode === 'verdict') return row.dataset.verdict || 'unknown';
        return row.dataset.container || 'unknown';
    }

    // bucketIndexFor returns the bucket containing the given event timestamp,
    // or -1 if it falls outside the current window. Used so historical
    // (replayed) events land in the bucket matching their wall-clock time
    // instead of all piling into "now".
    function bucketIndexFor(tsMs) {
        shiftIfNeeded();
        const nowBucketEnd = anchorBucketStart + BUCKET_MS;
        const offset = nowBucketEnd - tsMs;
        const i = BUCKETS - 1 - Math.floor(offset / BUCKET_MS);
        if (i < 0 || i >= BUCKETS) return -1;
        return i;
    }

    function onRowsAdded(mutations) {
        for (const m of mutations) {
            for (const node of m.addedNodes) {
                if (!(node instanceof HTMLElement) || node.tagName !== 'TR') continue;
                const ts = Number(node.dataset.ts) || Date.now();
                const idx = bucketIndexFor(ts);
                if (idx < 0) continue;
                const g = groupKey(node);
                const cnt = buckets[idx].get(g) || 0;
                buckets[idx].set(g, cnt + 1);
            }
        }
    }

    // rebucketFromDOM rebuilds the bucket counts from rows already in the
    // recent-traffic table. Called when the user toggles the group selector
    // so the chart keeps its history. The set of rows in #flow-rows is
    // bounded to MAX_ROWS by trimTable, which is also our practical chart
    // memory budget.
    function rebucketFromDOM() {
        const tbody = document.getElementById('flow-rows');
        if (!tbody) return;
        const rows = tbody.querySelectorAll('tr');
        for (let i = 0; i < rows.length; i++) {
            const tr = rows[i];
            const ts = Number(tr.dataset.ts);
            if (!ts) continue;
            const idx = bucketIndexFor(ts);
            if (idx < 0) continue;
            const g = groupKey(tr);
            buckets[idx].set(g, (buckets[idx].get(g) || 0) + 1);
        }
    }

    // currentBucketIndex returns the bucket index whose right edge is "now".
    // We anchor the window to a multiple of BUCKET_MS so all clients align.
    let anchorBucketStart = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;

    function currentBucketIndex() {
        shiftIfNeeded();
        return BUCKETS - 1;
    }

    function shiftIfNeeded() {
        const nowBucketStart = Math.floor(Date.now() / BUCKET_MS) * BUCKET_MS;
        const diff = Math.round((nowBucketStart - anchorBucketStart) / BUCKET_MS);
        if (diff <= 0) return;
        for (let i = 0; i < diff && i < BUCKETS; i++) {
            buckets.shift();
            buckets.push(new Map());
        }
        if (diff >= BUCKETS) buckets = newBuckets();
        anchorBucketStart = nowBucketStart;
    }

    function emptyData() {
        const t = new Array(BUCKETS);
        for (let i = 0; i < BUCKETS; i++) {
            t[i] = (anchorBucketStart - (BUCKETS - 1 - i) * BUCKET_MS) / 1000;
        }
        return [t, new Array(BUCKETS).fill(0)];
    }

    function redraw() {
        if (!chart) return;
        shiftIfNeeded();

        // Collect every group key present in the window.
        const groupSet = new Set();
        for (const b of buckets) for (const g of b.keys()) groupSet.add(g);
        const groups = Array.from(groupSet).sort();

        // Build x-axis (right edge of each bucket, in seconds since epoch).
        const t = new Array(BUCKETS);
        for (let i = 0; i < BUCKETS; i++) {
            t[i] = (anchorBucketStart - (BUCKETS - 1 - i) * BUCKET_MS) / 1000;
        }

        // Build one series per group.
        const data = [t];
        for (const g of groups) {
            const ser = new Array(BUCKETS);
            for (let i = 0; i < BUCKETS; i++) ser[i] = buckets[i].get(g) || 0;
            data.push(ser);
        }

        // uPlot doesn't support adding series after construction — rebuild.
        rebuildChart(groups);
        chart.setData(data);
    }

    function rebuildChart(groups) {
        const mount = document.getElementById('chart');
        const desired = ['time', ...groups].join('|');
        if (chart._blockyKey === desired) return;

        const series = [{ label: 'time' }];
        for (const g of groups) {
            series.push({
                label: g,
                stroke: pickColour(g),
                fill: pickColour(g) + '40',
                paths: uPlot.paths.bars({ size: [0.85, 6] }),
                points: { show: false },
            });
        }
        chart.destroy();
        chart = new uPlot({
            width: mount.clientWidth,
            height: chartCanvasHeight(mount),
            scales: { x: { time: true } },
            axes: [
                { stroke: getVar('--text-muted', '#94a3b8'), grid: { stroke: getVar('--border', '#1e293b') } },
                { stroke: getVar('--text-muted', '#94a3b8'), grid: { stroke: getVar('--border', '#1e293b') } },
            ],
            legend: { show: true },
            series,
            cursor: { drag: { x: false, y: false } },
        }, emptyData(), mount);
        chart._blockyKey = desired;
    }

    function trimTable(tbody) {
        while (tbody.children.length > MAX_ROWS) {
            tbody.removeChild(tbody.lastElementChild);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
})();
