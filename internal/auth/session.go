package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/act-security/terraform-provider-act/internal/retry"
)

const refreshBefore = 2 * time.Minute

type Config struct {
	Endpoint     Endpoint
	TenantID     string
	ClientID     string
	ClientSecret string
	HTTPClient   *http.Client
	UserAgent    string
	Now          func() time.Time
	Retry        retry.Policy
}

type Session struct {
	TenantID  string
	Region    string
	APIOrigin string

	sts   *stsClient
	mu    sync.Mutex
	token Token
}

func NewSession(ctx context.Context, cfg Config) (*Session, error) {
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("client_id and client_secret are both required")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	sts := &stsClient{
		endpoint:     cfg.Endpoint,
		httpClient:   cfg.HTTPClient,
		userAgent:    cfg.UserAgent,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
		now:          now,
		retry:        stsRetry(cfg.Retry),
	}

	discoveryToken, err := sts.mint(ctx, DiscoveryAudience(cfg.Endpoint.Origin))
	if err != nil {
		return nil, err
	}
	tenantID := cfg.TenantID
	switch {
	case tenantID == "" && discoveryToken.Tenant == "":
		return nil, ErrNoTenant
	case tenantID == "":
		tenantID = discoveryToken.Tenant
	case discoveryToken.Tenant != "" && discoveryToken.Tenant != tenantID:
		return nil, ErrTenantNotFound
	}
	d, err := sts.discover(ctx, discoveryToken, tenantID)
	if err != nil {
		return nil, err
	}
	if d.TenantID != tenantID {
		return nil, fmt.Errorf("the STS answered for tenant %q, not %q", d.TenantID, tenantID)
	}
	apiOrigin, err := CanonicalOrigin(d.PublicAPIURL)
	if err != nil {
		return nil, fmt.Errorf("the STS returned an unusable public API URL: %w", err)
	}
	if !cfg.Endpoint.apiOriginAllowed(apiOrigin) {
		return nil, fmt.Errorf("the STS returned public API URL %q, which this build does not accept", apiOrigin)
	}

	token, err := sts.mint(ctx, apiOrigin)
	if err != nil {
		return nil, err
	}
	return &Session{
		TenantID:  tenantID,
		Region:    d.Region,
		APIOrigin: apiOrigin,
		sts:       sts,
		token:     token,
	}, nil
}

func stsRetry(p retry.Policy) retry.Policy {
	p.RetryUnsafeMethods = true
	return p
}

func (s *Session) RefreshAccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	token, err := s.sts.mint(ctx, s.APIOrigin)
	if err != nil {
		return "", err
	}
	s.token = token
	return token.Value, nil
}

func (s *Session) AccessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sts.now().Add(refreshBefore).Before(s.token.Expiry) {
		return s.token.Value, nil
	}
	token, err := s.sts.mint(ctx, s.APIOrigin)
	if err != nil {
		return "", err
	}
	s.token = token
	return token.Value, nil
}
