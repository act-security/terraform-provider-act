package retry_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/act-security/terraform-provider-act/internal/retry"
)

type step struct {
	status int
	header map[string]string
	body   string
}

type recorder struct {
	waits []time.Duration
}

func (r *recorder) policy() retry.Policy {
	return retry.Policy{
		MaxAttempts:   4,
		BaseDelay:     100 * time.Millisecond,
		MaxDelay:      time.Second,
		MaxRetryAfter: 10 * time.Second,
		Sleep: func(_ context.Context, d time.Duration) error {
			r.waits = append(r.waits, d)
			return nil
		},
		Jitter: func(d time.Duration) time.Duration { return d },
		Now:    func() time.Time { return time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC) },
	}
}

func serve(t *testing.T, steps ...step) (*httptest.Server, *atomic.Int32, *[]string) {
	t.Helper()
	var calls atomic.Int32
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		bodies = append(bodies, string(body))
		i := int(calls.Add(1)) - 1
		s := step{status: http.StatusOK, body: `{"ok":true}`}
		if i < len(steps) {
			s = steps[i]
		}
		for k, v := range s.header {
			w.Header().Set(k, v)
		}
		w.WriteHeader(s.status)
		if _, err := io.WriteString(w, s.body); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls, &bodies
}

func do(t *testing.T, p retry.Policy, method, url, body string) (int, string, error) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := retry.Do(http.DefaultClient, req, p)
	if err != nil {
		return 0, "", err
	}
	got, err := io.ReadAll(resp.Body)
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Error(closeErr)
	}
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(got), nil
}

func TestRetriesTransientStatuses(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			rec := &recorder{}
			srv, calls, _ := serve(t, step{status: status})
			status, body, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
			if err != nil || status != http.StatusOK || body != `{"ok":true}` {
				t.Fatalf("got %d %v %q", status, err, body)
			}
			if calls.Load() != 2 || len(rec.waits) != 1 || rec.waits[0] != 100*time.Millisecond {
				t.Fatalf("calls %d waits %v", calls.Load(), rec.waits)
			}
		})
	}
}

func TestBacksOffExponentiallyAndStopsAtMaxAttempts(t *testing.T) {
	rec := &recorder{}
	busy := step{status: http.StatusServiceUnavailable, body: `{"error":{"code":"unavailable"}}`}
	srv, calls, _ := serve(t, busy, busy, busy, busy, busy)
	status, body, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err != nil || status != http.StatusServiceUnavailable || !strings.Contains(body, "unavailable") {
		t.Fatalf("got %d %v %q", status, err, body)
	}
	want := []time.Duration{100 * time.Millisecond, 200 * time.Millisecond, 400 * time.Millisecond}
	if calls.Load() != 4 || len(rec.waits) != 3 || rec.waits[0] != want[0] || rec.waits[1] != want[1] || rec.waits[2] != want[2] {
		t.Fatalf("calls %d waits %v, want 4 calls and %v", calls.Load(), rec.waits, want)
	}
}

func TestHonorsRetryAfter(t *testing.T) {
	rec := &recorder{}
	srv, calls, _ := serve(t,
		step{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "3"}},
		step{status: http.StatusServiceUnavailable, header: map[string]string{"Retry-After": "Sun, 08 Nov 2026 12:00:05 GMT"}},
	)
	status, _, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err != nil || status != http.StatusOK || calls.Load() != 3 {
		t.Fatalf("got %d %v after %d calls", status, err, calls.Load())
	}
	if rec.waits[0] != 3*time.Second || rec.waits[1] != 5*time.Second {
		t.Fatalf("waits %v, want 3s then 5s", rec.waits)
	}
}

func TestGivesUpWhenRetryAfterIsTooLong(t *testing.T) {
	rec := &recorder{}
	srv, calls, _ := serve(t, step{status: http.StatusTooManyRequests, header: map[string]string{"Retry-After": "3600"}, body: "slow down"})
	status, body, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err != nil || status != http.StatusTooManyRequests || body != "slow down" || calls.Load() != 1 {
		t.Fatalf("got %d %v %q after %d calls", status, err, body, calls.Load())
	}
}

func TestRetriesOtherServerErrorsOnlyWhenMarkedRetryable(t *testing.T) {
	rec := &recorder{}
	srv, calls, _ := serve(t, step{status: http.StatusInternalServerError, body: `{"error":{"code":"internal","retryable":true}}`})
	status, _, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err != nil || status != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("retryable 500: got %d %v after %d calls", status, err, calls.Load())
	}

	srv, calls, _ = serve(t, step{status: http.StatusInternalServerError, body: `{"error":{"code":"internal","retryable":false}}`})
	status, body, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err != nil || status != http.StatusInternalServerError || !strings.Contains(body, `"retryable":false`) || calls.Load() != 1 {
		t.Fatalf("final 500: got %d %v %q after %d calls", status, err, body, calls.Load())
	}
}

func TestDoesNotRetryClientErrors(t *testing.T) {
	for _, want := range []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict} {
		rec := &recorder{}
		srv, calls, _ := serve(t, step{status: want})
		status, _, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
		if err != nil || status != want || calls.Load() != 1 {
			t.Fatalf("%d: got %d %v after %d calls", want, status, err, calls.Load())
		}
	}
}

func TestPostIsRetriedOnlyWhenAllowed(t *testing.T) {
	rec := &recorder{}
	srv, calls, _ := serve(t, step{status: http.StatusServiceUnavailable})
	status, _, err := do(t, rec.policy(), http.MethodPost, srv.URL, "a=1")
	if err != nil || status != http.StatusServiceUnavailable || calls.Load() != 1 {
		t.Fatalf("POST by default: got %d %v after %d calls", status, err, calls.Load())
	}

	p := rec.policy()
	p.RetryUnsafeMethods = true
	srv, calls, bodies := serve(t, step{status: http.StatusServiceUnavailable})
	status, _, err = do(t, p, http.MethodPost, srv.URL, "a=1")
	if err != nil || status != http.StatusOK || calls.Load() != 2 {
		t.Fatalf("POST when allowed: got %d %v after %d calls", status, err, calls.Load())
	}
	if len(*bodies) != 2 || (*bodies)[0] != "a=1" || (*bodies)[1] != "a=1" {
		t.Fatalf("the retried POST did not resend its body: %q", *bodies)
	}
}

func TestPostWithAnIdempotencyKeyIsRetriedWithTheSameKey(t *testing.T) {
	rec := &recorder{}
	var keys []string
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(srv.Close)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, srv.URL, strings.NewReader(`{"name":"a"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Idempotency-Key", "tf-key")
	resp, err := retry.Do(http.DefaultClient, req, rec.policy())
	if err != nil {
		t.Fatal(err)
	}
	if closeErr := resp.Body.Close(); closeErr != nil {
		t.Error(closeErr)
	}
	if resp.StatusCode != http.StatusCreated || len(keys) != 2 || keys[0] != "tf-key" || keys[1] != "tf-key" {
		t.Fatalf("got %d with keys %q", resp.StatusCode, keys)
	}
}

func TestRetriesConnectionErrors(t *testing.T) {
	rec := &recorder{}
	srv, calls, _ := serve(t)
	url := srv.URL
	srv.Close()
	_, _, err := do(t, rec.policy(), http.MethodGet, url, "")
	if err == nil || calls.Load() != 0 || len(rec.waits) != 3 {
		t.Fatalf("got %v after %d calls and waits %v, want an error after 4 attempts", err, calls.Load(), rec.waits)
	}
}

func TestDoesNotRetryCertificateErrors(t *testing.T) {
	rec := &recorder{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(srv.Close)
	_, _, err := do(t, rec.policy(), http.MethodGet, srv.URL, "")
	if err == nil || len(rec.waits) != 0 {
		t.Fatalf("got %v with waits %v, want an immediate certificate error", err, rec.waits)
	}
}

func TestStopsWhenTheContextEnds(t *testing.T) {
	srv, calls, _ := serve(t, step{status: http.StatusServiceUnavailable}, step{status: http.StatusServiceUnavailable})
	p := retry.Policy{
		Sleep: func(ctx context.Context, _ time.Duration) error { return context.Canceled },
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := retry.Do(http.DefaultClient, req, p)
	if err == nil {
		if closeErr := resp.Body.Close(); closeErr != nil {
			t.Error(closeErr)
		}
		t.Fatal("got a response, want the sleep's context error")
	}
	if !errors.Is(err, context.Canceled) || calls.Load() != 1 {
		t.Fatalf("got %v after %d calls, want context.Canceled after 1", err, calls.Load())
	}
}
