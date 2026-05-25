package api

import (
	"context"
	"net/http"

	"blocky/internal/tap"
	"blocky/internal/types"
	"github.com/danielgtaylor/huma/v2"
)

type flowsOutput struct {
	Body struct {
		Flows []types.FlowEvent `json:"flows" doc:"Recent flow events, oldest first. Bounded by BLOCKY_FLOW_CACHE_SIZE."`
	}
}

func registerFlows(api huma.API, cache *tap.FlowCache) {
	huma.Register(api, huma.Operation{
		OperationID: "flows",
		Method:      http.MethodGet,
		Path:        "/v1/flows",
		Summary:     "Recent flow events from the in-memory ring buffer",
	}, func(_ context.Context, _ *struct{}) (*flowsOutput, error) {
		var out flowsOutput
		out.Body.Flows = cache.Snapshot()
		return &out, nil
	})
}
