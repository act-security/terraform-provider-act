package provider

import (
	"context"
	"crypto/rand"
	"errors"
	"math/big"
	"time"

	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	retryClassPropagation = "propagation"
	codeVerificationFail  = "verification_failed"
)

type verificationPolicy struct {
	budget time.Duration
	base   time.Duration
	max    time.Duration
	factor float64
	sleep  func(ctx context.Context, d time.Duration) error
	jitter func(d time.Duration) time.Duration
	now    func() time.Time
}

var awsVerification = verificationPolicy{
	budget: 2 * time.Minute,
	base:   5 * time.Second,
	max:    30 * time.Second,
	factor: 1.5,
	sleep:  sleepContext,
	jitter: fullJitter,
	now:    time.Now,
}

type verificationFailure struct {
	retryClass     string
	cloudErrorCode string
	attribute      string
	hint           string
	err            *client.APIError
}

type verificationOutcome struct {
	attempts int
	elapsed  time.Duration
	last     *verificationFailure
	timedOut bool
}

func asVerificationFailure(err error) (*verificationFailure, bool) {
	var apiErr *client.APIError
	if !errors.As(err, &apiErr) || apiErr.Code != codeVerificationFail {
		return nil, false
	}
	return &verificationFailure{
		retryClass:     apiErr.Detail("retryClass"),
		cloudErrorCode: apiErr.Detail("cloudErrorCode"),
		attribute:      apiErr.Detail("attribute"),
		hint:           apiErr.Detail("hint"),
		err:            apiErr,
	}, true
}

func (f *verificationFailure) sameAs(other *verificationFailure) bool {
	return other != nil && f.retryClass == other.retryClass && f.cloudErrorCode == other.cloudErrorCode && f.attribute == other.attribute
}

func (p verificationPolicy) run(ctx context.Context, call func(ctx context.Context) error) (verificationOutcome, error) {
	start := p.now()
	outcome := verificationOutcome{}
	delay := p.base
	for {
		outcome.attempts++
		err := call(ctx)
		outcome.elapsed = p.now().Sub(start)
		if err == nil {
			return outcome, nil
		}
		failure, ok := asVerificationFailure(err)
		if !ok {
			return outcome, err
		}
		repeated := failure.retryClass != retryClassPropagation && failure.sameAs(outcome.last)
		outcome.last = failure
		if repeated {
			return outcome, err
		}
		wait := p.jitter(delay)
		delay = min(time.Duration(float64(delay)*p.factor), p.max)
		if outcome.elapsed+wait > p.budget {
			outcome.timedOut = true
			return outcome, err
		}
		if deadline, ok := ctx.Deadline(); ok && p.now().Add(wait).After(deadline) {
			outcome.timedOut = true
			return outcome, err
		}
		if sleepErr := p.sleep(ctx, wait); sleepErr != nil {
			outcome.timedOut = true
			return outcome, err
		}
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func fullJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(d)+1))
	if err != nil {
		return d
	}
	return time.Duration(n.Int64())
}
