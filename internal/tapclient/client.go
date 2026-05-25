// Package tapclient implements the client side of `blocky tap`.
//
// It dials the daemon's /v1/tap WebSocket, applies filter query parameters, and
// renders each received FlowEvent to stdout in either pretty (tabular) or JSON form.
package tapclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"blocky/internal/types"
	"github.com/gorilla/websocket"
)

// Options configures a single tap session.
type Options struct {
	Addr      string    // host:port of the daemon
	Container string    // optional filter
	Verdict   string    // "allow"|"drop"|"" (no filter)
	Format    string    // "pretty"|"json"
	Stdout    io.Writer // where to render
}

// Run dials the daemon and prints events until ctx is canceled or the connection drops.
func Run(ctx context.Context, opts Options) error {
	u := url.URL{
		Scheme: "ws",
		Host:   opts.Addr,
		Path:   "/v1/tap",
	}
	q := u.Query()
	if opts.Container != "" {
		q.Set("container", opts.Container)
	}
	if opts.Verdict != "" {
		q.Set("verdict", strings.ToLower(opts.Verdict))
	}
	u.RawQuery = q.Encode()

	dialer := websocket.DefaultDialer
	dialer.HandshakeTimeout = 5 * time.Second

	conn, _, err := dialer.DialContext(ctx, u.String(), nil)
	if err != nil {
		return fmt.Errorf("dial %s: %w", u.String(), err)
	}
	defer func() { _ = conn.Close() }()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	const rowFmt = "%-23s  %-8s  %-12s  %-15s  %-21s  %s"
	if opts.Format == "pretty" {
		_, _ = fmt.Fprintf(opts.Stdout, rowFmt+"\n",
			"TIME", "VERDICT", "CONTAINER", "DST", "NAME", "REASON")
	}
	for {
		var ev types.FlowEvent
		if err := conn.ReadJSON(&ev); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read: %w", err)
		}
		if opts.Format == "json" {
			_ = json.NewEncoder(opts.Stdout).Encode(&ev)
			continue
		}
		cn := ev.ContainerName
		if cn == "" {
			cn = ev.ContainerID
		}
		if len(cn) > 12 {
			cn = cn[:12]
		}
		name := ev.Name
		if len(name) > 21 {
			name = name[:18] + "..."
		}
		_, _ = fmt.Fprintf(opts.Stdout, rowFmt+"\n",
			ev.Timestamp.Format("2006-01-02T15:04:05.000"),
			string(ev.Verdict),
			cn,
			fmt.Sprintf("%s:%d", ev.DstIP, ev.DstPort),
			name,
			string(ev.Reason),
		)
	}
}
