package auth_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/act-security/terraform-provider-act/internal/auth"
	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

func federated(source auth.CITokenSource) func(*auth.Config) {
	return func(c *auth.Config) {
		c.ClientSecret = ""
		c.CIToken = source
	}
}

func stsTokenRequests(s *fakeapi.Servers) int {
	count := 0
	for _, r := range s.Recorder().Requests() {
		if r.Method == http.MethodPost && r.Path == "/oidc/oauth2/token" {
			count++
		}
	}
	return count
}

func TestSessionSignsInWithACIToken(t *testing.T) {
	s := fakeapi.Start(t)
	session, err := newSession(t, s, federated(auth.StaticCIToken(fakeapi.CIToken(t, s.STSOrigin(), nil))))
	if err != nil {
		t.Fatal(err)
	}
	if token, err := session.RefreshAccessToken(t.Context()); err != nil || token == "" {
		t.Fatalf("RefreshAccessToken() = %q, %v", token, err)
	}
	if got := stsTokenRequests(s); got != 3 {
		t.Fatalf("the provider made %d token requests, want 3", got)
	}
}

func TestSessionNeverSendsACITokenForAnotherAudience(t *testing.T) {
	tests := map[string]any{
		"another audience":      "sts.amazonaws.com",
		"a second audience":     []string{"https://placeholder", "sts.amazonaws.com"},
		"the token endpoint":    "/oidc/oauth2/token",
		"no audience":           nil,
		"the origin with slash": "/",
	}
	for name, audience := range tests {
		t.Run(name, func(t *testing.T) {
			s := fakeapi.Start(t)
			if path, ok := audience.(string); ok && strings.HasPrefix(path, "/") {
				audience = s.STSOrigin() + path
			}
			_, err := newSession(t, s, federated(auth.StaticCIToken(fakeapi.CIToken(t, audience, nil))))
			if err == nil || !strings.Contains(err.Error(), "audience") {
				t.Fatalf("NewSession error = %v, want an audience error", err)
			}
			if got := stsTokenRequests(s); got != 0 {
				t.Fatalf("the provider sent the CI token to the STS %d times", got)
			}
		})
	}
}

func TestSessionRefusesATokenThatIsNotAJWT(t *testing.T) {
	s := fakeapi.Start(t)
	if _, err := newSession(t, s, federated(auth.StaticCIToken("not-a-jwt"))); err == nil {
		t.Fatal("NewSession accepted a CI token that is not a JWT")
	}
	if got := stsTokenRequests(s); got != 0 {
		t.Fatalf("the provider sent a malformed CI token to the STS %d times", got)
	}
}

func TestSessionReportsATrustPolicyRefusal(t *testing.T) {
	s := fakeapi.Start(t)
	token := fakeapi.CIToken(t, s.STSOrigin(), map[string]any{"iss": "https://untrusted.example"})
	_, err := newSession(t, s, federated(auth.StaticCIToken(token)))
	if !errors.Is(err, auth.ErrFederationRefused) {
		t.Fatalf("NewSession error = %v, want ErrFederationRefused", err)
	}
}

func TestSessionRereadsTheTokenFileOnEveryMint(t *testing.T) {
	s := fakeapi.Start(t)
	file := filepath.Join(t.TempDir(), "token")
	write := func(token string) {
		if err := os.WriteFile(file, []byte(token+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(fakeapi.CIToken(t, s.STSOrigin(), nil))
	session, err := newSession(t, s, federated(auth.FileCIToken(file)))
	if err != nil {
		t.Fatal(err)
	}

	write(fakeapi.CIToken(t, "sts.amazonaws.com", nil))
	if _, err := session.RefreshAccessToken(t.Context()); err == nil || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("RefreshAccessToken error = %v, want the rewritten file's audience refused", err)
	}
}

func TestSessionReadsTheTokenFromTheEnvironmentOnEveryMint(t *testing.T) {
	s := fakeapi.Start(t)
	env := map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN_ACT": fakeapi.CIToken(t, s.STSOrigin(), nil)}
	source := auth.EnvCIToken("TFC_WORKLOAD_IDENTITY_TOKEN_ACT", func(name string) string { return env[name] })
	session, err := newSession(t, s, federated(source))
	if err != nil {
		t.Fatal(err)
	}

	env["TFC_WORKLOAD_IDENTITY_TOKEN_ACT"] = ""
	if _, err := session.RefreshAccessToken(t.Context()); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("RefreshAccessToken error = %v, want the emptied variable reported", err)
	}
}

func TestSessionRequestsAGitHubActionsTokenForTheSTSOnEveryMint(t *testing.T) {
	s := fakeapi.Start(t)
	var requests atomic.Int32
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer request-token" || r.URL.Query().Get("api-version") != "2.0" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		body, err := json.Marshal(map[string]string{"value": fakeapi.CIToken(t, r.URL.Query().Get("audience"), nil)})
		if err != nil {
			t.Error(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(github.Close)

	source := auth.GitHubActionsCIToken(github.URL+"/token?api-version=2.0", "request-token", http.DefaultClient, retry.Default())
	session, err := newSession(t, s, federated(source))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.RefreshAccessToken(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("the provider asked GitHub for %d tokens, want one per mint (3)", got)
	}
}

func TestSessionExplainsAGitHubActionsJobWithoutIDTokenPermission(t *testing.T) {
	s := fakeapi.Start(t)
	github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(github.Close)

	source := auth.GitHubActionsCIToken(github.URL, "request-token", http.DefaultClient, retry.Default())
	_, err := newSession(t, s, federated(source))
	if err == nil || !strings.Contains(err.Error(), "id-token: write") {
		t.Fatalf("NewSession error = %v, want a hint about id-token: write", err)
	}
	if got := stsTokenRequests(s); got != 0 {
		t.Fatalf("the provider made %d STS token requests without a CI token", got)
	}
}

func TestSessionNeedsExactlyOneCredential(t *testing.T) {
	s := fakeapi.Start(t)
	both := func(c *auth.Config) { c.CIToken = auth.StaticCIToken(fakeapi.CIToken(t, s.STSOrigin(), nil)) }
	neither := func(c *auth.Config) { c.ClientSecret = "" }
	for name, mutate := range map[string]func(*auth.Config){"both": both, "neither": neither} {
		t.Run(name, func(t *testing.T) {
			if _, err := newSession(t, s, mutate); err == nil {
				t.Fatal("NewSession accepted the credentials")
			}
		})
	}
}
