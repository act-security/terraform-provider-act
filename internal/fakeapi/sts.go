package fakeapi

import (
	"crypto/subtle"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

const (
	FederatedAssertionType = "urn:act:params:oauth:client-assertion-type:federated-identity-jwt"
	CIIssuer               = "https://ci.example.test"
)

func (f *Fake) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                f.stsOrigin,
		"token_endpoint":                        f.stsOrigin + "/oidc/oauth2/token",
		"jwks_uri":                              f.stsOrigin + "/oidc/jwks",
		"grant_types_supported":                 []string{"client_credentials"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
	})
}

func (f *Fake) jwks(w http.ResponseWriter, _ *http.Request) {
	keys, err := f.signer.jwks()
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, keys)
}

func (f *Fake) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "the body is not a form")
		return
	}
	if _, _, hasBasic := r.BasicAuth(); hasBasic {
		oauthError(w, http.StatusUnauthorized, "invalid_client", "client registered for client_secret_post cannot use client_secret_basic")
		return
	}
	if status, code, description := f.authenticateClient(r.PostForm); code != "" {
		oauthError(w, status, code, description)
		return
	}
	if r.PostForm.Get("grant_type") != "client_credentials" {
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "only client_credentials is supported")
		return
	}
	resource := r.PostForm.Get("resource")
	if resource != f.DiscoveryAudience() && resource != f.apiOrigin {
		oauthError(w, http.StatusBadRequest, "invalid_target", "resource must be the tenant discovery audience or the public API origin")
		return
	}

	now := f.now()
	claims := map[string]any{
		"iss":                                  f.stsOrigin,
		"sub":                                  f.cfg.ClientID,
		"aud":                                  resource,
		"iat":                                  now.Unix(),
		"exp":                                  now.Add(TokenLifetime).Unix(),
		"jti":                                  randomID("jti_"),
		"client_id":                            f.cfg.ClientID,
		"scope":                                "act:read",
		ClaimNamespace + "claims_version":      2,
		ClaimNamespace + "current_tenant":      f.cfg.TenantID,
		ClaimNamespace + "authentication_flow": "client_credentials",
		ClaimNamespace + "principal": map[string]any{
			"kind": "service_account",
			"name": DefaultServiceAccount,
		},
	}
	if f.cfg.OmitTenantClaim {
		delete(claims, ClaimNamespace+"current_tenant")
	}
	token, err := f.signer.sign(claims)
	if err != nil {
		oauthError(w, http.StatusInternalServerError, "server_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(TokenLifetime.Seconds()),
		"scope":        "act:read",
	})
}

func (f *Fake) discovery(w http.ResponseWriter, r *http.Request) {
	if _, ok := f.verifyBearer(r, f.DiscoveryAudience()); !ok {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token"})
		return
	}
	if r.PathValue("tenant_id") != f.cfg.TenantID {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "tenant_not_found"})
		return
	}
	if f.cfg.PublicAPIUnavailable {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "public_api_unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"tenantId":     f.cfg.TenantID,
		"region":       f.cfg.Region,
		"publicApiUrl": f.apiOrigin,
	})
}

func (f *Fake) authenticateClient(form url.Values) (int, string, string) {
	clientID := form.Get("client_id")
	if assertionType := form.Get("client_assertion_type"); assertionType != "" {
		if assertionType != FederatedAssertionType || form.Has("client_secret") {
			return http.StatusBadRequest, "invalid_request", "send either client_secret or a federated client_assertion"
		}
		if !f.trustedCIToken(clientID, form.Get("client_assertion")) {
			return http.StatusUnauthorized, "invalid_client", "service account does not accept this federated identity"
		}
		return 0, "", ""
	}
	clientSecret := form.Get("client_secret")
	if clientID == "" || clientSecret == "" {
		return http.StatusBadRequest, "invalid_request", "send client_id and client_secret as form fields"
	}
	if !f.validClient(clientID, clientSecret) {
		return http.StatusUnauthorized, "invalid_client", "client authentication failed"
	}
	return 0, "", ""
}

func (f *Fake) trustedCIToken(clientID, assertion string) bool {
	if subtle.ConstantTimeCompare([]byte(clientID), []byte(f.cfg.ClientID)) != 1 {
		return false
	}
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return false
	}
	var claims struct {
		Issuer   string `json:"iss"`
		Audience string `json:"aud"`
	}
	if err := decodePart(parts[1], &claims); err != nil {
		return false
	}
	return claims.Issuer == CIIssuer && claims.Audience == f.stsOrigin
}

func (f *Fake) validClient(id, secret string) bool {
	idOK := subtle.ConstantTimeCompare([]byte(id), []byte(f.cfg.ClientID)) == 1
	secretOK := subtle.ConstantTimeCompare([]byte(secret), []byte(f.cfg.ClientSecret)) == 1
	return idOK && secretOK
}

func (f *Fake) verifyBearer(r *http.Request, audience string) (map[string]any, bool) {
	raw, found := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !found || raw == "" {
		return nil, false
	}
	claims, err := f.signer.verify(raw, f.stsOrigin, audience, f.now())
	if err != nil {
		return nil, false
	}
	return claims, true
}

func oauthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		return
	}
}
