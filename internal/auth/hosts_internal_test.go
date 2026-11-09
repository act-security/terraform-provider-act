//go:build actinternal

package auth_test

import (
	"testing"

	"github.com/act-security/terraform-provider-act/internal/auth"
)

const (
	internalSTS = "https://auth.internal.example.test"
	internalAPI = "https://api.internal.example.test"
)

func TestInternalBuildAcceptsTheLinkedDevHosts(t *testing.T) {
	t.Cleanup(auth.SetInternalOrigins(internalSTS, internalAPI))

	got, err := auth.ResolveEndpoint(internalSTS)
	if err != nil {
		t.Fatalf("the internal build refused the dev STS: %v", err)
	}
	if got.Unsafe {
		t.Fatal("the dev STS must not count as an unsafe endpoint")
	}
	if !auth.APIOriginAllowed(internalAPI) {
		t.Fatal("the internal build refused the dev public API")
	}
	if auth.APIOriginAllowed("https://api.other.example.test") {
		t.Fatal("the internal build accepted a host outside its allow-list")
	}
}

func TestInternalBuildWithoutLinkedHostsAcceptsOnlyProduction(t *testing.T) {
	t.Cleanup(auth.SetInternalOrigins("", ""))

	if _, err := auth.ResolveEndpoint(internalSTS); err == nil {
		t.Fatal("an internal build without linked hosts accepted an unknown STS")
	}
	if got := auth.STSOrigins(); len(got) != 1 || got[0] != auth.ProductionSTSOrigin {
		t.Fatalf("STSOrigins() = %v, want only %s", got, auth.ProductionSTSOrigin)
	}
}

func TestInternalBuildAcceptsLoopbackOnlyWithTheUnsafeFlag(t *testing.T) {
	t.Setenv("ACT_ALLOW_UNSAFE_ENDPOINT", "1")
	for override, want := range map[string]auth.Endpoint{
		"http://127.0.0.1:8787": {Origin: "http://127.0.0.1:8787", Unsafe: true},
		"http://localhost:3002": {Origin: "http://localhost:3002", Unsafe: true},
	} {
		got, err := auth.ResolveEndpoint(override)
		if err != nil {
			t.Fatalf("ResolveEndpoint(%q): %v", override, err)
		}
		if got != want {
			t.Fatalf("ResolveEndpoint(%q) = %+v, want %+v", override, got, want)
		}
	}
	if _, err := auth.ResolveEndpoint("https://auth.example.com"); err == nil {
		t.Fatal("the unsafe flag let a foreign host through")
	}
}
