// Package api wires the HTTP/WebSocket surface using gin + huma.
//
// Typed REST endpoints (health, containers list/detail) are registered via huma
// so they generate OpenAPI. The /v1/tap WebSocket route is a plain gin handler
// because huma's request/response model does not fit a streaming upgrade.
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"blocky/internal/config"
	dnscache "blocky/internal/dns"
	"blocky/internal/reconciler"
	"blocky/internal/tap"
	"blocky/internal/web"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humagin"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
)

// Server bundles the gin engine + http.Server lifecycle.
type Server struct {
	cfg    config.Config
	log    zerolog.Logger
	engine *gin.Engine
	srv    *http.Server
}

// New builds a Server. The reconciler is the source for /v1/containers; the
// hub powers /v1/tap and the dashboard WS; the dns cache backs the dashboard's
// DNS view; the flow cache backs /v1/flows and WS replay-on-connect.
func New(cfg config.Config, log zerolog.Logger, rec *reconciler.Reconciler, hub *tap.Hub,
	cache *dnscache.Cache, flowCache *tap.FlowCache) *Server {
	gin.SetMode(gin.ReleaseMode)
	engine := gin.New()
	engine.Use(gin.Recovery())

	api := humagin.New(engine, huma.DefaultConfig("blocky", "0.1.0"))
	registerHealth(api)
	registerContainers(api, rec)
	registerFlows(api, flowCache)

	engine.GET("/v1/tap", gin.WrapF(tap.Handler(hub, log)))

	web.New(log, hub, rec, cache, cfg).Register(engine)

	return &Server{
		cfg:    cfg,
		log:    log,
		engine: engine,
		srv: &http.Server{
			Addr:              cfg.APIAddr,
			Handler:           engine,
			ReadHeaderTimeout: 5 * time.Second,
		},
	}
}

// Run blocks until ctx is canceled, then shuts the server down with a 5s grace.
func (s *Server) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		s.log.Info().Str("addr", s.cfg.APIAddr).Msg("http server listening")
		err := s.srv.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.srv.Shutdown(shutCtx)
		return nil
	case err := <-errCh:
		return err
	}
}
