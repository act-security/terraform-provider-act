package fakeapi

import (
	"fmt"
	"net/http"
	"time"
)

const (
	DefaultTenantID          = "00000000-0000-4000-8000-000000000001"
	DefaultTenantDisplayName = "Fake Tenant"
	DefaultRegion            = "us1"
	DefaultClientID          = "fake-client-0001"
	DefaultClientSecret      = "fake-secret-not-a-real-credential"
	DefaultServiceAccount    = "fake service account"
	ClaimNamespace           = "https://app.act.security/"
	DiscoveryPath            = "/oidc/tenants"
	TokenLifetime            = 15 * time.Minute
)

type Config struct {
	TenantID             string
	TenantDisplayName    string
	Region               string
	ClientID             string
	ClientSecret         string
	PublicAPIUnavailable bool
	OmitTenantClaim      bool
	Script               Script
}

func DefaultConfig() Config {
	return Config{
		TenantID:          DefaultTenantID,
		TenantDisplayName: DefaultTenantDisplayName,
		Region:            DefaultRegion,
		ClientID:          DefaultClientID,
		ClientSecret:      DefaultClientSecret,
	}
}

type Fake struct {
	cfg          Config
	stsOrigin    string
	apiOrigin    string
	signer       *signer
	script       *scriptQueue
	recorder     *Recorder
	now          func() time.Time
	integrations *integrationStore
	deployments  *deploymentStore
}

func New(cfg Config, stsOrigin, apiOrigin string) (*Fake, error) {
	if stsOrigin == apiOrigin {
		return nil, fmt.Errorf("the STS and API origins must differ, both are %q", stsOrigin)
	}
	s, err := newSigner()
	if err != nil {
		return nil, err
	}
	return &Fake{
		cfg:          cfg,
		stsOrigin:    stsOrigin,
		apiOrigin:    apiOrigin,
		signer:       s,
		script:       newScriptQueue(cfg.Script),
		recorder:     &Recorder{},
		now:          time.Now,
		integrations: newIntegrationStore(time.Now().UTC()),
		deployments:  newDeploymentStore(),
	}, nil
}

func (f *Fake) STSOrigin() string { return f.stsOrigin }

func (f *Fake) APIOrigin() string { return f.apiOrigin }

func (f *Fake) DiscoveryAudience() string { return f.stsOrigin + DiscoveryPath }

func (f *Fake) Recorder() *Recorder { return f.recorder }

func (f *Fake) STSHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", f.metadata)
	mux.HandleFunc("GET /oidc/jwks", f.jwks)
	mux.HandleFunc("POST /oidc/oauth2/token", f.token)
	mux.HandleFunc("GET "+DiscoveryPath+"/{tenant_id}", f.discovery)
	return f.wrap(OriginSTS, mux)
}

func (f *Fake) APIHandler() http.Handler {
	return f.wrap(OriginAPI, f.bearer(f.apiRoutes()))
}

func (f *Fake) wrap(origin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		if scripted, ok := f.script.next(r.Method + " " + r.URL.Path); ok {
			scripted.write(rec)
		} else {
			next.ServeHTTP(rec, r)
		}
		f.recorder.add(Request{
			Origin:    origin,
			Method:    r.Method,
			Path:      r.URL.Path,
			Status:    rec.status,
			UserAgent: r.UserAgent(),
		})
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}
