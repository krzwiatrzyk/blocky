package tap

import (
	"context"
	"net/http"
	"strings"
	"time"

	"blocky/internal/types"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog"
)

// Handler returns an http.HandlerFunc that upgrades the connection to WebSocket
// and forwards filtered events from hub. Filters come from query params:
//
//	?container=<id|name>
//	?verdict=allow|drop
func Handler(hub *Hub, log zerolog.Logger) http.HandlerFunc {
	up := websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 4096,
		CheckOrigin:     func(*http.Request) bool { return true },
	}
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := up.Upgrade(w, r, nil)
		if err != nil {
			log.Warn().Err(err).Msg("ws upgrade failed")
			return
		}
		defer func() { _ = conn.Close() }()

		f := SubscriberFilter{
			Container: r.URL.Query().Get("container"),
			Verdict:   types.Verdict(strings.ToLower(r.URL.Query().Get("verdict"))),
		}
		s := hub.Subscribe(f)
		defer hub.Unsubscribe(s)

		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()

		// One reader goroutine to detect client disconnects; ignore content.
		go func() {
			defer cancel()
			for {
				if _, _, err := conn.NextReader(); err != nil {
					return
				}
			}
		}()

		writeWait := 5 * time.Second
		for {
			select {
			case <-ctx.Done():
				return
			case ev, ok := <-s.Channel():
				if !ok {
					return
				}
				_ = conn.SetWriteDeadline(time.Now().Add(writeWait))
				if err := conn.WriteJSON(ev); err != nil {
					return
				}
			}
		}
	}
}
