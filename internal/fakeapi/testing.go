package fakeapi

import (
	"net/http/httptest"
	"testing"
)

type Option func(*Config)

func WithRegion(region string) Option {
	return func(c *Config) { c.Region = region }
}

func WithTenantID(id string) Option {
	return func(c *Config) { c.TenantID = id }
}

func WithPublicAPIUnavailable() Option {
	return func(c *Config) { c.PublicAPIUnavailable = true }
}

func WithNotificationRulesDisabled() Option {
	return func(c *Config) { c.NotificationRulesDisabled = true }
}

func WithoutTenantClaim() Option {
	return func(c *Config) { c.OmitTenantClaim = true }
}

func WithScript(s Script) Option {
	return func(c *Config) { c.Script = s }
}

type Servers struct {
	*Fake
	Config Config
	STS    *httptest.Server
	API    *httptest.Server
}

func Start(t testing.TB, opts ...Option) *Servers {
	t.Helper()
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	sts := httptest.NewUnstartedServer(nil)
	api := httptest.NewUnstartedServer(nil)
	fake, err := New(cfg, "http://"+sts.Listener.Addr().String(), "http://"+api.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	sts.Config.Handler = fake.STSHandler()
	api.Config.Handler = fake.APIHandler()
	sts.Start()
	api.Start()
	t.Cleanup(sts.Close)
	t.Cleanup(api.Close)
	return &Servers{Fake: fake, Config: cfg, STS: sts, API: api}
}

func (s *Servers) Setenv(t testing.TB) {
	t.Helper()
	t.Setenv("ACT_ENDPOINT", s.STSOrigin())
	t.Setenv("ACT_ALLOW_UNSAFE_ENDPOINT", "1")
	t.Setenv("ACT_TENANT_ID", s.Config.TenantID)
	t.Setenv("ACT_CLIENT_ID", s.Config.ClientID)
	t.Setenv("ACT_CLIENT_SECRET", s.Config.ClientSecret)
}
