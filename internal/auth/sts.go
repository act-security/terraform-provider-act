package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/act-security/terraform-provider-act/internal/retry"
)

const maxBodyBytes = 1 << 20

var (
	ErrInvalidClient        = errors.New("the Act STS rejected the client_id and client_secret")
	ErrTenantNotFound       = errors.New("the service account is not bound to this tenant_id, or the tenant does not exist")
	ErrNoTenant             = errors.New("the Act STS token does not name a tenant; set tenant_id")
	ErrPublicAPIUnavailable = errors.New("the Act public API is not available for this tenant yet")
)

type STSError struct {
	Status      int
	Code        string
	Description string
}

func (e *STSError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("Act STS returned %d %s: %s", e.Status, e.Code, e.Description)
	}
	return fmt.Sprintf("Act STS returned %d %s", e.Status, e.Code)
}

type Discovery struct {
	TenantID     string `json:"tenantId"`
	Region       string `json:"region"`
	PublicAPIURL string `json:"publicApiUrl"`
}

type stsClient struct {
	endpoint     Endpoint
	httpClient   *http.Client
	retry        retry.Policy
	userAgent    string
	clientID     string
	clientSecret string
	now          func() time.Time
}

func (s *stsClient) mint(ctx context.Context, resource string) (Token, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"resource":      {resource},
		"client_id":     {s.clientID},
		"client_secret": {s.clientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint.Origin+"/oidc/oauth2/token", strings.NewReader(form.Encode()))
	if err != nil {
		return Token{}, fmt.Errorf("building the token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.userAgent)

	status, body, err := s.do(req)
	if err != nil {
		return Token{}, err
	}
	if status != http.StatusOK {
		return Token{}, oauthError(status, body)
	}
	var tr struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if decodeErr := json.Unmarshal(body, &tr); decodeErr != nil {
		return Token{}, fmt.Errorf("decoding the token response: %w", decodeErr)
	}
	if !strings.EqualFold(tr.TokenType, "bearer") || tr.AccessToken == "" {
		return Token{}, fmt.Errorf("the STS returned token_type %q without a bearer token", tr.TokenType)
	}
	return checkToken(tr.AccessToken, s.endpoint.Origin, resource, s.now())
}

func (s *stsClient) discover(ctx context.Context, token Token, tenantID string) (Discovery, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint.Origin+DiscoveryPath+"/"+url.PathEscape(tenantID), http.NoBody)
	if err != nil {
		return Discovery{}, fmt.Errorf("building the discovery request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token.Value)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", s.userAgent)

	status, body, err := s.do(req)
	if err != nil {
		return Discovery{}, err
	}
	switch status {
	case http.StatusOK:
		var d Discovery
		if err := json.Unmarshal(body, &d); err != nil {
			return Discovery{}, fmt.Errorf("decoding the discovery response: %w", err)
		}
		return d, nil
	case http.StatusNotFound:
		if oauthCode(body) == "public_api_unavailable" {
			return Discovery{}, ErrPublicAPIUnavailable
		}
		return Discovery{}, ErrTenantNotFound
	default:
		return Discovery{}, oauthError(status, body)
	}
}

func (s *stsClient) do(req *http.Request) (int, []byte, error) {
	resp, err := retry.Do(s.httpClient, req, s.retry)
	if err != nil {
		return 0, nil, fmt.Errorf("calling the Act STS: %w", err)
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	closeErr := resp.Body.Close()
	if readErr != nil {
		return 0, nil, fmt.Errorf("reading the Act STS response: %w", readErr)
	}
	if closeErr != nil {
		return 0, nil, fmt.Errorf("closing the Act STS response: %w", closeErr)
	}
	return resp.StatusCode, body, nil
}

type oauthBody struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

func oauthCode(body []byte) string {
	var e oauthBody
	if json.Unmarshal(body, &e) != nil {
		return ""
	}
	return e.Error
}

func oauthError(status int, body []byte) error {
	var e oauthBody
	if json.Unmarshal(body, &e) != nil {
		e = oauthBody{}
	}
	if e.Error == "invalid_client" {
		return ErrInvalidClient
	}
	if e.Error == "" {
		e.Error = http.StatusText(status)
	}
	return &STSError{Status: status, Code: e.Error, Description: e.Description}
}
