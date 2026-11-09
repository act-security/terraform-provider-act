package client_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/act-security/terraform-provider-act/internal/client"
	"github.com/act-security/terraform-provider-act/internal/retry"
)

const whoamiBody = `{"tenantId":"00000000-0000-4000-8000-000000000001","tenantDisplayName":"Fake","region":"us1","principal":{"kind":"service_account","id":"c1","name":"sa"},"tokenScope":"act:read","scopes":["act:read"],"authMethod":"client_credentials"}`

type tokens struct {
	mu        sync.Mutex
	current   string
	refreshes int
	refresh   func(n int) (string, error)
}

func (s *tokens) AccessToken(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current, nil
}

func (s *tokens) RefreshAccessToken(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refreshes++
	token, err := s.refresh(s.refreshes)
	if err != nil {
		return "", err
	}
	s.current = token
	return token, nil
}

type reply struct {
	status int
	body   string
}

func api(t *testing.T, replies ...reply) (*httptest.Server, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var auth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		i := len(auth) - 1
		mu.Unlock()
		rep := reply{status: http.StatusOK, body: whoamiBody}
		if i < len(replies) {
			rep = replies[i]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(rep.status)
		if _, err := io.WriteString(w, rep.body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &auth
}

func fast() retry.Policy {
	return retry.Policy{Sleep: func(context.Context, time.Duration) error { return nil }}
}

const unauthenticated = `{"error":{"code":"unauthenticated","message":"A valid bearer token is required","requestId":"req_1","retryable":false}}`

func TestRefreshesTheTokenOnceAfterA401(t *testing.T) {
	srv, auth := api(t, reply{status: http.StatusUnauthorized, body: unauthenticated})
	src := &tokens{current: "old", refresh: func(int) (string, error) { return "new", nil }}
	c, err := client.New(srv.URL, src, srv.Client(), "test", fast())
	if err != nil {
		t.Fatal(err)
	}
	who, err := c.Whoami(t.Context())
	if err != nil || who.TenantDisplayName != "Fake" {
		t.Fatalf("whoami = %v, %v", who, err)
	}
	if src.refreshes != 1 || len(*auth) != 2 || (*auth)[0] != "Bearer old" || (*auth)[1] != "Bearer new" {
		t.Fatalf("refreshes %d, Authorization headers %q", src.refreshes, *auth)
	}
}

func TestReturnsTheSecond401(t *testing.T) {
	srv, auth := api(t, reply{status: http.StatusUnauthorized, body: unauthenticated}, reply{status: http.StatusUnauthorized, body: unauthenticated})
	src := &tokens{current: "old", refresh: func(int) (string, error) { return "new", nil }}
	c, err := client.New(srv.URL, src, srv.Client(), "test", fast())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Whoami(t.Context())
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.Status != http.StatusUnauthorized || apiErr.Code != "unauthenticated" {
		t.Fatalf("got %v, want the 401 envelope", err)
	}
	if src.refreshes != 1 || len(*auth) != 2 {
		t.Fatalf("refreshes %d after %d calls, want 1 refresh and 2 calls", src.refreshes, len(*auth))
	}
}

func TestReportsTheRefreshFailureAfterA401(t *testing.T) {
	srv, auth := api(t, reply{status: http.StatusUnauthorized, body: unauthenticated})
	src := &tokens{current: "old", refresh: func(int) (string, error) { return "", errors.New("sts down") }}
	c, err := client.New(srv.URL, src, srv.Client(), "test", fast())
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Whoami(t.Context())
	if err == nil || !strings.Contains(err.Error(), "rejected the token") || !strings.Contains(err.Error(), "sts down") || len(*auth) != 1 {
		t.Fatalf("got %v after %d calls, want the refresh failure after 1 call", err, len(*auth))
	}
}

func TestRetriesTransientErrorsWithoutRefreshing(t *testing.T) {
	srv, auth := api(t,
		reply{status: http.StatusServiceUnavailable, body: `{"error":{"code":"unavailable","retryable":true}}`},
		reply{status: http.StatusTooManyRequests, body: `{"error":{"code":"rate_limited","retryable":true}}`},
	)
	src := &tokens{current: "tok", refresh: func(int) (string, error) { return "new", nil }}
	c, err := client.New(srv.URL, src, srv.Client(), "test", fast())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Whoami(t.Context()); err != nil {
		t.Fatal(err)
	}
	if src.refreshes != 0 || len(*auth) != 3 {
		t.Fatalf("refreshes %d after %d calls, want 0 refreshes and 3 calls", src.refreshes, len(*auth))
	}
}
