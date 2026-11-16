package fakeapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

func TestAnOperationTheFakeLacksAnswers501(t *testing.T) {
	strict := gen.NewStrictHandlerWithOptions(gen.UnimplementedStrictServer{}, nil, strictOptions)
	handler := gen.HandlerWithOptions(strict, gen.StdHTTPServerOptions{BaseRouter: newRouter()})
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/whoami", http.NoBody))

	var body gen.ErrorEnvelope
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q is not an error envelope: %v", recorder.Body.String(), err)
	}
	if recorder.Code != http.StatusNotImplemented || body.Error.Code != gen.ErrorEnvelopeErrorCodeInternal {
		t.Fatalf("GET /v1/whoami = %d %+v, want 501 with code internal", recorder.Code, body.Error)
	}
}
