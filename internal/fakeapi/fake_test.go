package fakeapi_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

func mint(t *testing.T, s *fakeapi.Servers, resource string) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"resource":      {resource},
		"client_id":     {s.Config.ClientID},
		"client_secret": {s.Config.ClientSecret},
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.STSOrigin()+"/oidc/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return doJSON(t, req)
}

func TestTokenRejectsHTTPBasicLikeTheRealSTS(t *testing.T) {
	s := fakeapi.Start(t)
	form := url.Values{"grant_type": {"client_credentials"}, "resource": {s.DiscoveryAudience()}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, s.STSOrigin()+"/oidc/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.SetBasicAuth(s.Config.ClientID, s.Config.ClientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, body := doJSON(t, req)
	if status != http.StatusUnauthorized || body["error"] != "invalid_client" {
		t.Fatalf("HTTP Basic = %d %v, want 401 invalid_client", status, body)
	}
}

func token(t *testing.T, s *fakeapi.Servers, resource string) string {
	t.Helper()
	status, body := mint(t, s, resource)
	value, ok := body["access_token"].(string)
	if status != http.StatusOK || !ok {
		t.Fatalf("minting for %q = %d %v", resource, status, body)
	}
	return value
}

func get(t *testing.T, target, token string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return doJSON(t, req)
}

func doJSON(t *testing.T, req *http.Request) (int, map[string]any) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("%s %s: body %q is not JSON", req.Method, req.URL, body)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("%s %s: Cache-Control = %q, want no-store", req.Method, req.URL, cc)
	}
	return resp.StatusCode, out
}

func TestTokenResources(t *testing.T) {
	s := fakeapi.Start(t)
	for resource, want := range map[string]int{
		s.DiscoveryAudience():        http.StatusOK,
		s.APIOrigin():                http.StatusOK,
		s.STSOrigin():                http.StatusBadRequest,
		"https://api.us1.act.secure": http.StatusBadRequest,
	} {
		if status, body := mint(t, s, resource); status != want {
			t.Errorf("resource %q: status %d (%v), want %d", resource, status, body, want)
		}
	}
}

func TestDiscoveryNeedsTheDiscoveryAudience(t *testing.T) {
	s := fakeapi.Start(t)
	apiToken := token(t, s, s.APIOrigin())
	discoveryToken := token(t, s, s.DiscoveryAudience())
	target := s.STSOrigin() + "/oidc/tenants/" + s.Config.TenantID

	if status, body := get(t, target, apiToken); status != http.StatusUnauthorized || body["error"] != "invalid_token" {
		t.Fatalf("discovery with an API token = %d %v, want 401 invalid_token", status, body)
	}
	if status, body := get(t, target, discoveryToken); status != http.StatusOK || body["publicApiUrl"] != s.APIOrigin() {
		t.Fatalf("discovery = %d %v", status, body)
	}
	if status, body := get(t, s.STSOrigin()+"/oidc/tenants/00000000-0000-4000-8000-000000000009", discoveryToken); status != http.StatusNotFound || body["error"] != "tenant_not_found" {
		t.Fatalf("discovery of another tenant = %d %v, want 404 tenant_not_found", status, body)
	}
}

func TestAPINeedsTheAPIAudience(t *testing.T) {
	s := fakeapi.Start(t)
	discoveryToken := token(t, s, s.DiscoveryAudience())
	apiToken := token(t, s, s.APIOrigin())

	if status, _ := get(t, s.APIOrigin()+"/v1/whoami", ""); status != http.StatusUnauthorized {
		t.Fatalf("whoami without a token = %d, want 401", status)
	}
	if status, _ := get(t, s.APIOrigin()+"/v1/whoami", discoveryToken); status != http.StatusUnauthorized {
		t.Fatalf("whoami with a discovery token = %d, want 401", status)
	}
	status, whoami := get(t, s.APIOrigin()+"/v1/whoami", apiToken)
	if status != http.StatusOK || whoami["tenantId"] != s.Config.TenantID {
		t.Fatalf("whoami = %d %v", status, whoami)
	}
	status, envelope := get(t, s.APIOrigin()+"/v1/deployments", apiToken)
	errBody, ok := envelope["error"].(map[string]any)
	if status != http.StatusForbidden || !ok || errBody["code"] != "feature_disabled" {
		t.Fatalf("deployments = %d %v, want 403 feature_disabled", status, envelope)
	}
}

func TestLoadScript(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good.json")
	if err := os.WriteFile(good, []byte(`{"GET /v1/whoami":[{"status":503,"headers":{"Retry-After":"1"},"body":{"error":{"code":"unavailable"}}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	script, err := fakeapi.LoadScript(good)
	if err != nil || len(script["GET /v1/whoami"]) != 1 {
		t.Fatalf("LoadScript = %v, %v", script, err)
	}
	for name, content := range map[string]string{
		"unknown-field.json": `{"GET /v1/whoami":[{"status":200,"delay":5}]}`,
		"bad-status.json":    `{"GET /v1/whoami":[{"status":42}]}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := fakeapi.LoadScript(path); err == nil {
			t.Errorf("LoadScript(%s) accepted an invalid script", name)
		}
	}
}
