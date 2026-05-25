package web

import (
	"bytes"
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"blocky/internal/tap"
	"blocky/internal/types"
	"blocky/internal/web/views/components"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 8192,
	CheckOrigin:     func(*http.Request) bool { return true },
}

// WS upgrades to a WebSocket and streams pre-rendered <tr> HTML fragments for
// each FlowEvent that passes the per-connection filter. The filter starts at
// DefaultFilterFor(view) and is replaced atomically each time the client posts
// a filter update over the same WS connection (the htmx-ws extension's
// ws-send pattern).
//
// On connect, the handler replays the hub's flow-cache snapshot before
// entering the live loop. The hub returns snapshot + maxSnapshotSeq under its
// write lock; any live event with Seq ≤ maxSnapshotSeq is skipped as a
// defensive de-dup (the lock makes it unreachable in practice).
func (h *Handler) WS(c *gin.Context) {
	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		h.log.Warn().Err(err).Msg("dashboard ws upgrade failed")
		return
	}
	defer func() { _ = conn.Close() }()

	view := c.Query("view")
	var filter atomic.Pointer[Filter]
	initial := DefaultFilterFor(view)
	filter.Store(&initial)

	sub, snapshot, maxSnapshotSeq := h.hub.SubscribeWithSnapshot(tap.SubscriberFilter{})
	defer h.hub.Unsubscribe(sub)

	ctx, cancel := context.WithCancel(c.Request.Context())
	defer cancel()

	go h.readFilterMessages(ctx, cancel, conn, &filter)

	const writeWait = 5 * time.Second
	var buf bytes.Buffer
	writeRow := func(ev types.FlowEvent) error {
		buf.Reset()
		if err := components.FlowRow(ev).Render(ctx, &buf); err != nil {
			h.log.Warn().Err(err).Msg("render flow row")
			return err
		}
		_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
		return conn.WriteMessage(websocket.TextMessage, buf.Bytes())
	}

	// Replay history first. flow_row.templ uses afterbegin so the dashboard
	// renders newest-on-top; iterate snapshot oldest→newest so the natural
	// effect is to keep newest entries at index 0.
	for _, ev := range snapshot {
		f := filter.Load()
		if f == nil || !f.Matches(&ev) {
			continue
		}
		if err := writeRow(ev); err != nil {
			return
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Channel():
			if !ok {
				return
			}
			if ev.Seq != 0 && ev.Seq <= maxSnapshotSeq {
				continue
			}
			f := filter.Load()
			if f == nil || !f.Matches(&ev) {
				continue
			}
			if err := writeRow(ev); err != nil {
				return
			}
		}
	}
}

// readFilterMessages drains incoming WS frames. Each frame is a JSON object
// posted by the right-sidebar form (htmx-ws). Anything that doesn't parse is
// logged at debug level and ignored — the form may send partial input as the
// user types.
func (h *Handler) readFilterMessages(ctx context.Context, cancel context.CancelFunc,
	conn *websocket.Conn, filter *atomic.Pointer[Filter]) {
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return
		}
		f, err := ParseFilterMessage(msg)
		if err != nil {
			h.log.Debug().Err(err).Msg("bad filter message")
			continue
		}
		filter.Store(&f)
	}
}
