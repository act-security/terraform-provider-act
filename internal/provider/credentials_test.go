package provider

import (
	"errors"
	"net/http"
	"testing"

	"github.com/act-security/terraform-provider-act/internal/retry"
)

func TestResolveCredential(t *testing.T) {
	gitHub := map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example/?api-version=2.0", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "x"}
	tests := []struct {
		name       string
		in         credentialInputs
		env        map[string]string
		wantSecret string
		wantSource string
		wantErr    error
	}{
		{name: "client secret", in: credentialInputs{clientSecret: "s"}, wantSecret: "s"},
		{name: "oidc token", in: credentialInputs{oidcToken: "t"}, wantSource: "oidc_token"},
		{name: "oidc token file", in: credentialInputs{oidcTokenFile: "/token"}, wantSource: "oidc_token_file_path"},
		{name: "HCP Terraform tagged token first", in: credentialInputs{useOIDC: "true"}, env: map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN_ACT": "a", "TFC_WORKLOAD_IDENTITY_TOKEN": "b"}, wantSource: "TFC_WORKLOAD_IDENTITY_TOKEN_ACT"},
		{name: "HCP Terraform default token", in: credentialInputs{useOIDC: "1"}, env: map[string]string{"TFC_WORKLOAD_IDENTITY_TOKEN": "b"}, wantSource: "TFC_WORKLOAD_IDENTITY_TOKEN"},
		{name: "GitHub Actions", in: credentialInputs{useOIDC: "true"}, env: gitHub, wantSource: "GitHub Actions OIDC"},
		{name: "use_oidc off ignores CI variables", in: credentialInputs{useOIDC: "false"}, env: gitHub, wantErr: errNoCredentials},
		{name: "secret and oidc token", in: credentialInputs{clientSecret: "s", oidcToken: "t"}, wantErr: errBothCredentials},
		{name: "secret and use_oidc", in: credentialInputs{clientSecret: "s", useOIDC: "true"}, env: gitHub, wantErr: errBothCredentials},
		{name: "token and token file", in: credentialInputs{oidcToken: "t", oidcTokenFile: "/token"}, wantErr: errBothOIDCInputs},
		{name: "use_oidc outside CI", in: credentialInputs{useOIDC: "true"}, wantErr: errNoCIToken},
		{name: "GitHub request URL without its token", in: credentialInputs{useOIDC: "true"}, env: map[string]string{"ACTIONS_ID_TOKEN_REQUEST_URL": "https://token.example"}, wantErr: errNoCIToken},
		{name: "nothing", wantErr: errNoCredentials},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := resolveCredential(tt.in, ciEnvironment{
				getenv:     func(name string) string { return tt.env[name] },
				httpClient: http.DefaultClient,
				retry:      retry.Default(),
			})
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("resolveCredential error = %v, want %v", err, tt.wantErr)
			}
			if got.clientSecret != tt.wantSecret {
				t.Fatalf("client secret = %q, want %q", got.clientSecret, tt.wantSecret)
			}
			source := ""
			if got.ciToken != nil {
				source = got.ciToken.Describe()
			}
			if source != tt.wantSource {
				t.Fatalf("CI token source = %q, want %q", source, tt.wantSource)
			}
		})
	}
}

func TestResolveCredentialRefusesAnUnparsableUseOIDC(t *testing.T) {
	_, err := resolveCredential(credentialInputs{useOIDC: "yes please"}, ciEnvironment{getenv: func(string) string { return "" }})
	if err == nil {
		t.Fatal("resolveCredential accepted use_oidc = \"yes please\"")
	}
}
