package fakeapi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

const tokenType = "at+jwt"

type signer struct {
	key *ecdsa.PrivateKey
	kid string
}

func newSigner() (*signer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the signing key: %w", err)
	}
	pub, err := key.PublicKey.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encoding the public key: %w", err)
	}
	sum := sha256.Sum256(pub)
	return &signer{key: key, kid: hex.EncodeToString(sum[:8])}, nil
}

func (s *signer) sign(claims map[string]any) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": tokenType, "kid": s.kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(input))
	r, sVal, err := ecdsa.Sign(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	sVal.FillBytes(sig[32:])
	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *signer) verify(raw, issuer, audience string, now time.Time) (map[string]any, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, errors.New("not a JWT")
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := decodePart(parts[0], &header); err != nil {
		return nil, err
	}
	if header.Alg != "ES256" || header.Typ != tokenType || header.Kid != s.kid {
		return nil, errors.New("unexpected token header")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		return nil, errors.New("malformed signature")
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if !ecdsa.Verify(&s.key.PublicKey, digest[:], new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])) {
		return nil, errors.New("bad signature")
	}
	var claims map[string]any
	if err := decodePart(parts[1], &claims); err != nil {
		return nil, err
	}
	if claims["iss"] != issuer {
		return nil, errors.New("wrong issuer")
	}
	aud, ok := claims["aud"].(string)
	if !ok || aud != audience {
		return nil, errors.New("wrong audience")
	}
	exp, ok := claims["exp"].(float64)
	if !ok || !time.Unix(int64(exp), 0).After(now) {
		return nil, errors.New("expired")
	}
	return claims, nil
}

func (s *signer) jwks() (map[string]any, error) {
	pub, err := s.key.PublicKey.Bytes()
	if err != nil {
		return nil, err
	}
	enc := base64.RawURLEncoding.EncodeToString
	return map[string]any{"keys": []map[string]string{{
		"kty": "EC",
		"crv": "P-256",
		"x":   enc(pub[1:33]),
		"y":   enc(pub[33:65]),
		"kid": s.kid,
		"alg": "ES256",
		"use": "sig",
	}}}, nil
}

func decodePart(part string, into any) error {
	data, err := base64.RawURLEncoding.DecodeString(part)
	if err != nil {
		return errors.New("not base64url")
	}
	if err := json.Unmarshal(data, into); err != nil {
		return errors.New("not JSON")
	}
	return nil
}

func randomID(prefix string) string {
	return prefix + strings.ToLower(rand.Text())
}
