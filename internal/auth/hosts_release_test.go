//go:build !actinternal

package auth_test

import (
	"testing"

	"github.com/act-security/terraform-provider-act/internal/auth"
)

func TestReleaseBuildRejectsInternalHosts(t *testing.T) {
	if _, err := auth.ResolveEndpoint("https://auth.internal.example.test"); err == nil {
		t.Fatal("a release build accepted the dev STS")
	}
	if auth.APIOriginAllowed("https://api.internal.example.test") {
		t.Fatal("a release build accepted the dev public API")
	}
	if got := auth.STSOrigins(); len(got) != 1 || got[0] != auth.ProductionSTSOrigin {
		t.Fatalf("STSOrigins() = %v, want only %s", got, auth.ProductionSTSOrigin)
	}
}

func TestReleaseBuildIgnoresTheUnsafeFlag(t *testing.T) {
	t.Setenv("ACT_ALLOW_UNSAFE_ENDPOINT", "1")
	for _, override := range []string{"http://127.0.0.1:8787", "http://localhost:3002"} {
		if got, err := auth.ResolveEndpoint(override); err == nil {
			t.Fatalf("a release build accepted loopback STS %q as %+v", override, got)
		}
	}
}
