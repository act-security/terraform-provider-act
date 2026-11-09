package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/act-security/terraform-provider-act/internal/auth"
	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

func newSession(t *testing.T, s *fakeapi.Servers, mutate func(*auth.Config)) (*auth.Session, error) {
	t.Helper()
	cfg := auth.Config{
		Endpoint:     auth.Endpoint{Origin: s.STSOrigin(), Unsafe: true},
		TenantID:     s.Config.TenantID,
		ClientID:     s.Config.ClientID,
		ClientSecret: s.Config.ClientSecret,
		HTTPClient:   http.DefaultClient,
		UserAgent:    "terraform-provider-act/test",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return auth.NewSession(t.Context(), cfg)
}

func TestSessionDiscoversTheAPIAndMintsForIt(t *testing.T) {
	s := fakeapi.Start(t)
	session, err := newSession(t, s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if session.APIOrigin != s.APIOrigin() || session.Region != fakeapi.DefaultRegion {
		t.Fatalf("session = %+v, want API %s in %s", session, s.APIOrigin(), fakeapi.DefaultRegion)
	}
	token, err := session.AccessToken(t.Context())
	if err != nil || token == "" {
		t.Fatalf("AccessToken() = %q, %v", token, err)
	}

	var paths []string
	for _, r := range s.Recorder().Requests() {
		paths = append(paths, r.Method+" "+r.Path)
	}
	want := []string{"POST /oidc/oauth2/token", "GET /oidc/tenants/" + s.Config.TenantID, "POST /oidc/oauth2/token"}
	if strings.Join(paths, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", paths, want)
	}
}

func TestSessionErrors(t *testing.T) {
	tests := []struct {
		name    string
		opts    []fakeapi.Option
		mutate  func(*auth.Config)
		wantErr error
		wantMsg string
	}{
		{name: "wrong secret", mutate: func(c *auth.Config) { c.ClientSecret = "wrong" }, wantErr: auth.ErrInvalidClient},
		{name: "tenant the key is not bound to", mutate: func(c *auth.Config) { c.TenantID = "00000000-0000-4000-8000-000000000002" }, wantErr: auth.ErrTenantNotFound},
		{name: "cell without a public API", opts: []fakeapi.Option{fakeapi.WithPublicAPIUnavailable()}, wantErr: auth.ErrPublicAPIUnavailable},
		{name: "loopback API without the unsafe flag", mutate: func(c *auth.Config) { c.Endpoint.Unsafe = false }, wantMsg: "does not accept"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeapi.Start(t, tt.opts...)
			_, err := newSession(t, s, tt.mutate)
			if err == nil {
				t.Fatal("NewSession succeeded, want an error")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewSession error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantMsg != "" && !strings.Contains(err.Error(), tt.wantMsg) {
				t.Fatalf("NewSession error = %v, want it to mention %q", err, tt.wantMsg)
			}
		})
	}
}

func TestSessionRefusesAPIOriginsOffTheAllowList(t *testing.T) {
	for _, publicAPIURL := range []string{"https://api.evil.example", "https://api.us1.act.security/v1", "ftp://127.0.0.1:1"} {
		t.Run(publicAPIURL, func(t *testing.T) {
			body, err := json.Marshal(map[string]string{"tenantId": fakeapi.DefaultTenantID, "region": "us1", "publicApiUrl": publicAPIURL})
			if err != nil {
				t.Fatal(err)
			}
			s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
				"GET /oidc/tenants/" + fakeapi.DefaultTenantID: {{Status: http.StatusOK, Body: body}},
			}))
			if _, err := newSession(t, s, nil); err == nil {
				t.Fatalf("NewSession accepted public API URL %q", publicAPIURL)
			}
			if got := len(s.Recorder().Requests()); got != 2 {
				t.Fatalf("the provider made %d STS calls, want 2: no API token after an unacceptable discovery answer", got)
			}
		})
	}
}

func TestSessionChecksTheTokenItGets(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
		"POST /oidc/oauth2/token": {{Status: http.StatusOK, Body: json.RawMessage(`{"access_token":"a.b.c","token_type":"Bearer"}`)}},
	}))
	if _, err := newSession(t, s, nil); err == nil {
		t.Fatal("NewSession accepted a token that is not a JWT")
	}
}

func noWait(c *auth.Config) {
	c.Retry = retry.Policy{Sleep: func(context.Context, time.Duration) error { return nil }}
}

func requests(s *fakeapi.Servers) []string {
	var paths []string
	for _, r := range s.Recorder().Requests() {
		paths = append(paths, fmt.Sprintf("%s %s %d", r.Method, r.Path, r.Status))
	}
	return paths
}

func TestSessionRetriesTransientSTSErrors(t *testing.T) {
	discovery := "GET /oidc/tenants/" + fakeapi.DefaultTenantID
	s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
		"POST /oidc/oauth2/token": {{Status: http.StatusServiceUnavailable}},
		discovery:                 {{Status: http.StatusBadGateway}, {Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}}},
	}))
	session, err := newSession(t, s, noWait)
	if err != nil {
		t.Fatal(err)
	}
	if session.APIOrigin != s.APIOrigin() {
		t.Fatalf("APIOrigin = %q", session.APIOrigin)
	}
	want := []string{
		"POST /oidc/oauth2/token 503",
		"POST /oidc/oauth2/token 200",
		discovery + " 502",
		discovery + " 429",
		discovery + " 200",
		"POST /oidc/oauth2/token 200",
	}
	if got := requests(s); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestSessionDoesNotRetryRejectedCredentials(t *testing.T) {
	s := fakeapi.Start(t)
	_, err := newSession(t, s, func(c *auth.Config) {
		noWait(c)
		c.ClientSecret = "wrong"
	})
	if !errors.Is(err, auth.ErrInvalidClient) {
		t.Fatalf("err = %v, want ErrInvalidClient", err)
	}
	if got := requests(s); len(got) != 1 {
		t.Fatalf("requests = %v, want a single token request", got)
	}
}

func TestRefreshAccessTokenMintsANewToken(t *testing.T) {
	s := fakeapi.Start(t)
	session, err := newSession(t, s, noWait)
	if err != nil {
		t.Fatal(err)
	}
	before := len(s.Recorder().Requests())
	token, err := session.RefreshAccessToken(t.Context())
	if err != nil || token == "" {
		t.Fatalf("RefreshAccessToken() = %q, %v", token, err)
	}
	cached, err := session.AccessToken(t.Context())
	if err != nil || cached != token {
		t.Fatalf("AccessToken() = %q, %v, want the refreshed token", cached, err)
	}
	got := requests(s)[before:]
	if len(got) != 1 || got[0] != "POST /oidc/oauth2/token 200" {
		t.Fatalf("requests after refresh = %v, want one token request", got)
	}
}

func TestSessionReadsTheTenantFromTheToken(t *testing.T) {
	s := fakeapi.Start(t)
	session, err := newSession(t, s, func(c *auth.Config) { c.TenantID = "" })
	if err != nil {
		t.Fatal(err)
	}
	if session.TenantID != fakeapi.DefaultTenantID || session.APIOrigin != s.APIOrigin() {
		t.Fatalf("session = %+v, want tenant %s from the token", session, fakeapi.DefaultTenantID)
	}
	want := []string{"POST /oidc/oauth2/token 200", "GET /oidc/tenants/" + fakeapi.DefaultTenantID + " 200", "POST /oidc/oauth2/token 200"}
	if got := requests(s); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("requests = %v, want %v", got, want)
	}
}

func TestSessionNeedsATenantWhenTheTokenHasNone(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithoutTenantClaim())
	_, err := newSession(t, s, func(c *auth.Config) { c.TenantID = "" })
	if !errors.Is(err, auth.ErrNoTenant) {
		t.Fatalf("err = %v, want ErrNoTenant", err)
	}

	session, err := newSession(t, s, nil)
	if err != nil || session.TenantID != fakeapi.DefaultTenantID {
		t.Fatalf("with tenant_id set: session = %+v, %v", session, err)
	}
}

func TestSessionRefusesATenantIDTheTokenContradicts(t *testing.T) {
	s := fakeapi.Start(t)
	_, err := newSession(t, s, func(c *auth.Config) { c.TenantID = "00000000-0000-4000-8000-000000000002" })
	if !errors.Is(err, auth.ErrTenantNotFound) {
		t.Fatalf("err = %v, want ErrTenantNotFound", err)
	}
	if got := requests(s); len(got) != 1 || got[0] != "POST /oidc/oauth2/token 200" {
		t.Fatalf("requests = %v, want only the discovery token", got)
	}
}
