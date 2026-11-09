package auth_test

import (
	"testing"

	"github.com/act-security/terraform-provider-act/internal/auth"
)

func TestResolveEndpoint(t *testing.T) {
	tests := []struct {
		name     string
		override string
		want     auth.Endpoint
		wantErr  bool
	}{
		{name: "default is production", want: auth.Endpoint{Origin: auth.ProductionSTSOrigin}},
		{name: "production by name", override: "https://auth.act.security", want: auth.Endpoint{Origin: auth.ProductionSTSOrigin}},
		{name: "trailing slash and case", override: "https://AUTH.act.security/", want: auth.Endpoint{Origin: auth.ProductionSTSOrigin}},
		{name: "loopback without the unsafe flag", override: "http://127.0.0.1:8787", wantErr: true},
		{name: "foreign host", override: "https://auth.example.com", wantErr: true},
		{name: "a path is not an origin", override: "https://auth.act.security/oidc", wantErr: true},
		{name: "userinfo is refused", override: "https://user@auth.act.security", wantErr: true},
		{name: "a query is refused", override: "https://auth.act.security?x=1", wantErr: true},
		{name: "plain http production", override: "http://auth.act.security", wantErr: true},
		{name: "another scheme", override: "ftp://auth.act.security", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := auth.ResolveEndpoint(tt.override)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("ResolveEndpoint(%q) = %+v, want an error", tt.override, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveEndpoint(%q): %v", tt.override, err)
			}
			if got != tt.want {
				t.Fatalf("ResolveEndpoint(%q) = %+v, want %+v", tt.override, got, tt.want)
			}
		})
	}
}

func TestAPIOriginAllowed(t *testing.T) {
	for origin, want := range map[string]bool{
		"https://api.us1.act.security":       true,
		"https://api.eu1.act.security":       true,
		"https://api.us1.act.security/":      false,
		"http://api.us1.act.security":        false,
		"https://api.act.security":           false,
		"https://api.us1.act.security.evil":  false,
		"https://evil.api.us1.act.security":  false,
		"https://api.-bad.act.security":      false,
		"https://api.us1.act.security:8443":  false,
		"https://auth.act.security":          false,
		"https://api.us1.act.securityx":      false,
		"https://api.us1.act.security\n.com": false,
	} {
		if got := auth.APIOriginAllowed(origin); got != want {
			t.Errorf("APIOriginAllowed(%q) = %v, want %v", origin, got, want)
		}
	}
}
