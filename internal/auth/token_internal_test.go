package auth

import (
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func jwt(t *testing.T, header, claims map[string]any) string {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	c, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c) + ".sig"
}

func TestCheckToken(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	good := map[string]any{"iss": "https://auth.act.security", "aud": "https://api.us1.act.security", "exp": now.Add(time.Minute).Unix()}
	with := func(k string, v any) map[string]any {
		c := map[string]any{}
		for key, val := range good {
			c[key] = val
		}
		c[k] = v
		return c
	}
	atJWT := map[string]any{"typ": "at+jwt", "alg": "ES256"}
	tests := []struct {
		name    string
		header  map[string]any
		claims  map[string]any
		wantErr bool
	}{
		{name: "valid", header: atJWT, claims: good},
		{name: "audience list", header: atJWT, claims: with("aud", []string{"x", "https://api.us1.act.security"})},
		{name: "application/at+jwt", header: map[string]any{"typ": "application/at+jwt"}, claims: good},
		{name: "plain JWT type", header: map[string]any{"typ": "JWT"}, claims: good, wantErr: true},
		{name: "wrong issuer", header: atJWT, claims: with("iss", "https://login.act.security/"), wantErr: true},
		{name: "wrong audience", header: atJWT, claims: with("aud", "https://auth.act.security"), wantErr: true},
		{name: "expired", header: atJWT, claims: with("exp", now.Unix()), wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkToken(jwt(t, tt.header, tt.claims), "https://auth.act.security", "https://api.us1.act.security", now)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkToken error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
	if _, err := checkToken("not-a-jwt", "x", "y", now); err == nil {
		t.Fatal("checkToken accepted a non-JWT")
	}

	raw := jwt(t, atJWT, with("https://app.act.security/current_tenant", "00000000-0000-4000-8000-000000000001"))
	token, err := checkToken(raw, "https://auth.act.security", "https://api.us1.act.security", now)
	if err != nil || token.Tenant != "00000000-0000-4000-8000-000000000001" || token.Value != raw || !token.Expiry.After(now) {
		t.Fatalf("checkToken = %+v, %v, want the token with its tenant claim", token, err)
	}
}
