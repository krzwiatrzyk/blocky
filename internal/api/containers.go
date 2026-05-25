package api

import (
	"context"
	"net/http"

	"blocky/internal/reconciler"
	"blocky/internal/types"
	"github.com/danielgtaylor/huma/v2"
)

type listContainersOutput struct {
	Body struct {
		Containers []types.Container `json:"containers"`
	}
}

type getContainerInput struct {
	ID string `path:"id" doc:"Container ID (or unique prefix)"`
}

type getContainerOutput struct {
	Body types.Container
}

func registerContainers(api huma.API, rec *reconciler.Reconciler) {
	huma.Register(api, huma.Operation{
		OperationID: "list-containers",
		Method:      http.MethodGet,
		Path:        "/v1/containers",
		Summary:     "List containers known to the daemon",
	}, func(_ context.Context, _ *struct{}) (*listContainersOutput, error) {
		var out listContainersOutput
		out.Body.Containers = rec.Snapshot()
		return &out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-container",
		Method:      http.MethodGet,
		Path:        "/v1/containers/{id}",
		Summary:     "Show one container's policy + state",
	}, func(_ context.Context, in *getContainerInput) (*getContainerOutput, error) {
		c, ok := rec.Get(in.ID)
		if !ok {
			return nil, huma.Error404NotFound("container not found")
		}
		return &getContainerOutput{Body: c}, nil
	})
}
