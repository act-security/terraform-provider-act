package fakeapi

import (
	"context"
	"net/http"
	"time"

	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
)

type claimsKey struct{}

func (f *Fake) bearer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		claims, ok := f.verifyBearer(r, f.apiOrigin)
		if !ok {
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			writeJSON(w, http.StatusUnauthorized, envelope(gen.ErrorEnvelopeErrorCodeUnauthenticated, "Missing or invalid bearer token."))
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), claimsKey{}, claims)))
	})
}

func (f *Fake) apiRoutes() http.Handler {
	return gen.HandlerWithOptions(gen.NewStrictHandler(&apiServer{fake: f}, nil), gen.StdHTTPServerOptions{
		ErrorHandlerFunc: func(w http.ResponseWriter, _ *http.Request, err error) {
			writeJSON(w, http.StatusBadRequest, envelope(gen.ErrorEnvelopeErrorCodeInvalidRequest, err.Error()))
		},
	})
}

type apiServer struct {
	fake *Fake
}

var _ gen.StrictServerInterface = (*apiServer)(nil)

func (s *apiServer) GetWhoami(ctx context.Context, _ gen.GetWhoamiRequestObject) (gen.GetWhoamiResponseObject, error) {
	expiry := time.Now().Add(TokenLifetime).UTC()
	if claims, ok := ctx.Value(claimsKey{}).(map[string]any); ok {
		if exp, ok := claims["exp"].(float64); ok {
			expiry = time.Unix(int64(exp), 0).UTC()
		}
	}
	region := s.fake.cfg.Region
	return gen.GetWhoami200JSONResponse{
		TenantID:          s.fake.cfg.TenantID,
		TenantDisplayName: s.fake.cfg.TenantDisplayName,
		Region:            &region,
		Principal: gen.Principal{
			ID:   s.fake.cfg.ClientID,
			Kind: gen.PrincipalKindServiceAccount,
			Name: DefaultServiceAccount,
		},
		TokenScope:     gen.TokenScopeActRead,
		Scopes:         []string{"act:read"},
		AuthMethod:     gen.AuthMethodClientCredentials,
		TokenExpiresAt: expiry,
	}, nil
}

func (s *apiServer) GetAwsOnboarding(context.Context, gen.GetAwsOnboardingRequestObject) (gen.GetAwsOnboardingResponseObject, error) {
	return gen.GetAwsOnboarding403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetAzureOnboarding(context.Context, gen.GetAzureOnboardingRequestObject) (gen.GetAzureOnboardingResponseObject, error) {
	return gen.GetAzureOnboarding403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetGcpOnboarding(context.Context, gen.GetGcpOnboardingRequestObject) (gen.GetGcpOnboardingResponseObject, error) {
	return gen.GetGcpOnboarding403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) ListDeployments(context.Context, gen.ListDeploymentsRequestObject) (gen.ListDeploymentsResponseObject, error) {
	return gen.ListDeployments403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetAwsDeployment(context.Context, gen.GetAwsDeploymentRequestObject) (gen.GetAwsDeploymentResponseObject, error) {
	return gen.GetAwsDeployment403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetAzureDeployment(context.Context, gen.GetAzureDeploymentRequestObject) (gen.GetAzureDeploymentResponseObject, error) {
	return gen.GetAzureDeployment403JSONResponse{Body: featureDisabled()}, nil
}

func (s *apiServer) GetGcpDeployment(context.Context, gen.GetGcpDeploymentRequestObject) (gen.GetGcpDeploymentResponseObject, error) {
	return gen.GetGcpDeployment403JSONResponse{Body: featureDisabled()}, nil
}

func featureDisabled() gen.ErrorEnvelope {
	return envelope(gen.ErrorEnvelopeErrorCodeFeatureDisabled, "This endpoint is not enabled for the tenant yet.")
}

func envelope(code gen.ErrorEnvelopeErrorCode, message string) gen.ErrorEnvelope {
	var e gen.ErrorEnvelope
	e.Error.Code = code
	e.Error.Message = message
	e.Error.RequestID = randomID("req_")
	return e
}
