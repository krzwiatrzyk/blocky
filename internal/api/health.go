package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type healthOutput struct {
	Body struct {
		Status string `json:"status" example:"ok" doc:"Daemon liveness status"`
	}
}

func registerHealth(api huma.API) {
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/v1/health",
		Summary:     "Daemon health probe",
	}, func(_ context.Context, _ *struct{}) (*healthOutput, error) {
		var out healthOutput
		out.Body.Status = "ok"
		return &out, nil
	})
}
