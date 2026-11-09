package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

type Token struct {
	Value  string
	Expiry time.Time
	Tenant string
}

type audience []string

func (a *audience) UnmarshalJSON(data []byte) error {
	var single string
	if err := json.Unmarshal(data, &single); err == nil {
		*a = audience{single}
		return nil
	}
	var many []string
	if err := json.Unmarshal(data, &many); err != nil {
		return errors.New("aud is neither a string nor a list of strings")
	}
	*a = many
	return nil
}

type tokenHeader struct {
	Type string `json:"typ"`
}

type tokenClaims struct {
	Issuer        string   `json:"iss"`
	Audience      audience `json:"aud"`
	Expiry        int64    `json:"exp"`
	CurrentTenant string   `json:"https://app.act.security/current_tenant"`
}

func checkToken(raw, wantIssuer, wantAudience string, now time.Time) (Token, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return Token{}, errors.New("the STS returned a token that is not a JWT")
	}
	var header tokenHeader
	if err := decodeSegment(parts[0], &header); err != nil {
		return Token{}, fmt.Errorf("token header: %w", err)
	}
	if typ := strings.ToLower(header.Type); typ != "at+jwt" && typ != "application/at+jwt" {
		return Token{}, fmt.Errorf("token type %q is not at+jwt", header.Type)
	}
	var claims tokenClaims
	if err := decodeSegment(parts[1], &claims); err != nil {
		return Token{}, fmt.Errorf("token claims: %w", err)
	}
	if claims.Issuer != wantIssuer {
		return Token{}, fmt.Errorf("token issuer %q is not the STS %q", claims.Issuer, wantIssuer)
	}
	if !slices.Contains(claims.Audience, wantAudience) {
		return Token{}, fmt.Errorf("token audience %v does not include %q", []string(claims.Audience), wantAudience)
	}
	expiry := time.Unix(claims.Expiry, 0)
	if !expiry.After(now) {
		return Token{}, errors.New("the STS returned an expired token")
	}
	return Token{Value: raw, Expiry: expiry, Tenant: claims.CurrentTenant}, nil
}

func decodeSegment(segment string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		return fmt.Errorf("not base64url: %w", err)
	}
	if err := json.Unmarshal(data, into); err != nil {
		return fmt.Errorf("not JSON: %w", err)
	}
	return nil
}
