package retry

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"time"
)

const peekLimit = 1 << 20

type Doer interface {
	Do(req *http.Request) (*http.Response, error)
}

type Policy struct {
	MaxAttempts        int
	BaseDelay          time.Duration
	MaxDelay           time.Duration
	MaxRetryAfter      time.Duration
	RetryUnsafeMethods bool
	Sleep              func(ctx context.Context, d time.Duration) error
	Jitter             func(d time.Duration) time.Duration
	Now                func() time.Time
}

func Default() Policy {
	return Policy{
		MaxAttempts:   4,
		BaseDelay:     500 * time.Millisecond,
		MaxDelay:      8 * time.Second,
		MaxRetryAfter: 30 * time.Second,
	}
}

func (p Policy) withDefaults() Policy {
	d := Default()
	if p.MaxAttempts <= 0 {
		p.MaxAttempts = d.MaxAttempts
	}
	if p.BaseDelay <= 0 {
		p.BaseDelay = d.BaseDelay
	}
	if p.MaxDelay <= 0 {
		p.MaxDelay = d.MaxDelay
	}
	if p.MaxRetryAfter <= 0 {
		p.MaxRetryAfter = d.MaxRetryAfter
	}
	if p.Sleep == nil {
		p.Sleep = sleep
	}
	if p.Jitter == nil {
		p.Jitter = halfJitter
	}
	if p.Now == nil {
		p.Now = time.Now
	}
	return p
}

func Do(doer Doer, req *http.Request, policy Policy) (*http.Response, error) {
	p := policy.withDefaults()
	ctx := req.Context()
	retriable := p.RetryUnsafeMethods || idempotent(req.Method) || req.Header.Get("Idempotency-Key") != ""
	for attempt := 1; ; attempt++ {
		r, err := forAttempt(req, attempt)
		if err != nil {
			return nil, err
		}
		resp, err := doer.Do(r)
		last := !retriable || attempt >= p.MaxAttempts || !replayable(req)
		if err != nil {
			if last || ctx.Err() != nil || !transient(err) {
				return nil, err
			}
			if sleepErr := p.Sleep(ctx, p.backoff(attempt)); sleepErr != nil {
				return nil, err
			}
			continue
		}
		wait, retry := p.classify(resp, attempt)
		if !retry || last {
			return resp, nil
		}
		if err = discard(resp); err != nil {
			return nil, err
		}
		if sleepErr := p.Sleep(ctx, wait); sleepErr != nil {
			return nil, sleepErr
		}
	}
}

func (p Policy) classify(resp *http.Response, attempt int) (time.Duration, bool) {
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
	default:
		if resp.StatusCode < 500 || resp.StatusCode > 599 {
			return 0, false
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, peekLimit))
		if closeErr := resp.Body.Close(); err == nil {
			err = closeErr
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil || !retryableEnvelope(body) {
			return 0, false
		}
	}
	wait := p.backoff(attempt)
	if after, ok := p.retryAfter(resp.Header.Get("Retry-After")); ok {
		if after > p.MaxRetryAfter {
			return 0, false
		}
		if after > wait {
			wait = after
		}
	}
	return wait, true
}

func (p Policy) backoff(attempt int) time.Duration {
	d := p.BaseDelay << (attempt - 1)
	if d <= 0 || d > p.MaxDelay {
		d = p.MaxDelay
	}
	return p.Jitter(d)
}

func (p Policy) retryAfter(value string) (time.Duration, bool) {
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds < 0 {
			return 0, false
		}
		return time.Duration(seconds) * time.Second, true
	}
	if at, err := http.ParseTime(value); err == nil {
		d := at.Sub(p.Now())
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}

func retryableEnvelope(body []byte) bool {
	var envelope struct {
		Error struct {
			Retryable bool `json:"retryable"`
		} `json:"error"`
	}
	return json.Unmarshal(body, &envelope) == nil && envelope.Error.Retryable
}

func transient(err error) bool {
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var verification *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return false
	case errors.As(err, &unknownAuthority), errors.As(err, &hostname), errors.As(err, &invalid), errors.As(err, &verification):
		return false
	default:
		return true
	}
}

func idempotent(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodPut, http.MethodDelete:
		return true
	default:
		return false
	}
}

func replayable(req *http.Request) bool {
	return req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
}

func forAttempt(req *http.Request, attempt int) (*http.Request, error) {
	if attempt == 1 {
		return req, nil
	}
	r := req.Clone(req.Context())
	if req.Body != nil && req.Body != http.NoBody {
		body, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r.Body = body
	}
	return r, nil
}

func discard(resp *http.Response) error {
	if _, err := io.Copy(io.Discard, io.LimitReader(resp.Body, peekLimit)); err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func halfJitter(d time.Duration) time.Duration {
	half := d / 2
	if half <= 0 {
		return d
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(half)+1))
	if err != nil {
		return d
	}
	return half + time.Duration(n.Int64())
}
