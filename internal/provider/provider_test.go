//go:build actinternal

package provider_test

import (
	"net/http"
	"os"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

const requiredProviders = `
terraform {
  required_providers {
    act = {
      source = "act-security/act"
    }
  }
}
`

func TestMain(m *testing.M) {
	if os.Getenv("TF_ACC_PROVIDER_NAMESPACE") == "" {
		if err := os.Setenv("TF_ACC_PROVIDER_NAMESPACE", "act-security"); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func factories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"act": providerserver.NewProtocol6WithError(provider.New("test")()),
	}
}

func identityConfig(providerBlock string) string {
	return requiredProviders + providerBlock + `
data "act_current_identity" "this" {}
`
}

func TestCurrentIdentity(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: identityConfig(`provider "act" {
  region = "us1"
}
`),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("tenant_id"), knownvalue.StringExact(fakeapi.DefaultTenantID)),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("tenant_display_name"), knownvalue.StringExact(fakeapi.DefaultTenantDisplayName)),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("region"), knownvalue.StringExact(fakeapi.DefaultRegion)),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("principal_kind"), knownvalue.StringExact("service_account")),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("principal_id"), knownvalue.StringExact(fakeapi.DefaultClientID)),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("principal_role"), knownvalue.Null()),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("token_scope"), knownvalue.StringExact("act:read")),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("scopes"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("act:read")})),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("auth_method"), knownvalue.StringExact("client_credentials")),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("federation_issuer"), knownvalue.Null()),
			},
		}},
	})

	for _, r := range s.Recorder().Requests() {
		if r.Origin == fakeapi.OriginAPI && r.Method != http.MethodGet {
			t.Errorf("the provider sent %s %s to the public API during a read-only run", r.Method, r.Path)
		}
		if r.UserAgent == "" || !regexp.MustCompile(`^terraform-provider-act/test terraform/`).MatchString(r.UserAgent) {
			t.Errorf("request %s %s carried User-Agent %q", r.Method, r.Path, r.UserAgent)
		}
	}
}

func TestProviderConfigurationErrors(t *testing.T) {
	tests := []struct {
		name     string
		opts     []fakeapi.Option
		env      map[string]string
		provider string
		want     string
	}{
		{
			name:     "tenant the key is not bound to",
			provider: `provider "act" { tenant_id = "00000000-0000-4000-8000-000000000002" }`,
			want:     `not bound to this tenant_id`,
		},
		{
			name:     "region mismatch",
			provider: `provider "act" { region = "eu1" }`,
			want:     `lives in region "us1"`,
		},
		{
			name: "public API not available yet",
			opts: []fakeapi.Option{fakeapi.WithPublicAPIUnavailable()},
			want: `not available for this tenant yet`,
		},
		{
			name: "loopback STS without the unsafe flag",
			env:  map[string]string{"ACT_ALLOW_UNSAFE_ENDPOINT": ""},
			want: `not an Act STS origin`,
		},
		{
			name: "wrong client secret",
			env:  map[string]string{"ACT_CLIENT_SECRET": "wrong"},
			want: `rejected the client_id and client_secret`,
		},
		{
			name:     "uppercase tenant ID",
			provider: `provider "act" { tenant_id = "00000000-0000-4000-8000-00000000000A" }`,
			want:     `must be a lowercase UUID`,
		},
		{
			name: "missing secret",
			env:  map[string]string{"ACT_CLIENT_SECRET": ""},
			want: `Missing client_secret`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeapi.Start(t, tt.opts...)
			s.Setenv(t)
			for k, v := range tt.env {
				t.Setenv(k, v)
			}
			providerBlock := tt.provider
			if providerBlock == "" {
				providerBlock = `provider "act" {}`
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: factories(),
				Steps: []resource.TestStep{{
					Config:      identityConfig(providerBlock + "\n"),
					ExpectError: regexp.MustCompile(regexp.QuoteMeta(tt.want)),
				}},
			})
		})
	}
}

func whoamiCalls(s *fakeapi.Servers) (int, int) {
	calls, mints := 0, 0
	for _, r := range s.Recorder().Requests() {
		switch {
		case r.Origin == fakeapi.OriginAPI && r.Path == "/v1/whoami":
			calls++
		case r.Method == http.MethodPost && r.Path == "/oidc/oauth2/token":
			mints++
		}
	}
	return calls, mints
}

func TestCurrentIdentityRidesOutTransientAPIErrors(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
		"GET /v1/whoami": {
			{Status: http.StatusServiceUnavailable, Body: []byte(`{"error":{"code":"unavailable","message":"try again","requestId":"req_1","retryable":true}}`)},
			{Status: http.StatusTooManyRequests, Headers: map[string]string{"Retry-After": "1"}, Body: []byte(`{"error":{"code":"rate_limited","message":"slow down","requestId":"req_2","retryable":true}}`)},
		},
	}))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: identityConfig(`provider "act" {}` + "\n"),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("tenant_id"), knownvalue.StringExact(fakeapi.DefaultTenantID)),
			},
		}},
	})

	if calls, _ := whoamiCalls(s); calls < 3 {
		t.Fatalf("whoami was called %d times, want the 503 and 429 retried", calls)
	}
}

func TestCurrentIdentityRefreshesTheTokenAfterA401(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
		"GET /v1/whoami": {
			{Status: http.StatusUnauthorized, Body: []byte(`{"error":{"code":"unauthenticated","message":"A valid bearer token is required","requestId":"req_1","retryable":false}}`)},
		},
	}))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: identityConfig(`provider "act" {}` + "\n"),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("tenant_id"), knownvalue.StringExact(fakeapi.DefaultTenantID)),
			},
		}},
	})

	requests := s.Recorder().Requests()
	for i, r := range requests {
		if r.Path != "/v1/whoami" || r.Status != http.StatusUnauthorized {
			continue
		}
		if i+2 >= len(requests) || requests[i+1].Path != "/oidc/oauth2/token" || requests[i+2].Path != "/v1/whoami" || requests[i+2].Status != http.StatusOK {
			t.Fatalf("after the 401 the provider sent %v, want a token request then a successful whoami", requests[i+1:])
		}
		return
	}
	t.Fatal("the scripted 401 was never served")
}

func TestCurrentIdentityGivesUpAfterRepeatedServerErrors(t *testing.T) {
	busy := fakeapi.ScriptResponse{Status: http.StatusServiceUnavailable, Body: []byte(`{"error":{"code":"unavailable","message":"down","requestId":"req_1","retryable":true}}`)}
	s := fakeapi.Start(t, fakeapi.WithScript(fakeapi.Script{
		"GET /v1/whoami": {busy, busy, busy, busy},
	}))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      identityConfig(`provider "act" {}` + "\n"),
			ExpectError: regexp.MustCompile(`Act API returned 503 unavailable`),
		}},
	})

	if calls, _ := whoamiCalls(s); calls != 4 {
		t.Fatalf("whoami was called %d times, want 4 attempts", calls)
	}
}

func TestCurrentIdentityWithoutTenantID(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	t.Setenv("ACT_TENANT_ID", "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: identityConfig(`provider "act" {}` + "\n"),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("tenant_id"), knownvalue.StringExact(fakeapi.DefaultTenantID)),
				statecheck.ExpectKnownValue("data.act_current_identity.this", tfjsonpath.New("region"), knownvalue.StringExact(fakeapi.DefaultRegion)),
			},
		}},
	})
}

func TestTenantIDIsNeededWhenTheTokenNamesNoTenant(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithoutTenantClaim())
	s.Setenv(t)
	t.Setenv("ACT_TENANT_ID", "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      identityConfig(`provider "act" {}` + "\n"),
			ExpectError: regexp.MustCompile(`does not name a tenant; set tenant_id`),
		}},
	})
}
