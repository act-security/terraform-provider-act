package provider

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/act-security/terraform-provider-act/internal/client"
)

type fakeClock struct {
	now   time.Time
	waits []time.Duration
}

func (c *fakeClock) policy(budget time.Duration) verificationPolicy {
	return verificationPolicy{
		budget: budget,
		base:   5 * time.Second,
		max:    30 * time.Second,
		factor: 1.5,
		now:    func() time.Time { return c.now },
		jitter: func(d time.Duration) time.Duration { return d },
		sleep: func(_ context.Context, d time.Duration) error {
			c.waits = append(c.waits, d)
			c.now = c.now.Add(d)
			return nil
		},
	}
}

func failure(retryClass, code string) error {
	return &client.APIError{
		Status:  422,
		Code:    codeVerificationFail,
		Details: map[string]any{"retryClass": retryClass, "cloudErrorCode": code, "attribute": "roleArn"},
	}
}

func answers(errs ...error) (func(context.Context) error, *int) {
	calls := 0
	return func(context.Context) error {
		calls++
		if calls <= len(errs) {
			return errs[calls-1]
		}
		return nil
	}, &calls
}

func TestVerificationRetriesPropagationUntilItSucceeds(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	call, calls := answers(failure("propagation", "AccessDenied"), failure("propagation", "AccessDenied"))
	outcome, err := clock.policy(2*time.Minute).run(t.Context(), call)
	if err != nil || *calls != 3 || outcome.attempts != 3 {
		t.Fatalf("got %v after %d calls", err, *calls)
	}
	if len(clock.waits) != 2 || clock.waits[0] != 5*time.Second || clock.waits[1] != 7500*time.Millisecond {
		t.Fatalf("waits %v, want 5s then 7.5s", clock.waits)
	}
}

func TestVerificationGivesUpOnPropagationAfterTheBudget(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	errs := make([]error, 50)
	for i := range errs {
		errs[i] = failure("propagation", "AccessDenied")
	}
	call, calls := answers(errs...)
	outcome, err := clock.policy(2*time.Minute).run(t.Context(), call)
	if err == nil || !outcome.timedOut {
		t.Fatalf("want a timeout, got %v", err)
	}
	if outcome.elapsed > 2*time.Minute || *calls < 5 {
		t.Fatalf("elapsed %s after %d calls", outcome.elapsed, *calls)
	}
	for _, wait := range clock.waits {
		if wait > 30*time.Second {
			t.Fatalf("wait %s above the cap", wait)
		}
	}
}

func TestVerificationStopsAfterTwoIdenticalDeterministicAnswers(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	call, calls := answers(failure("deterministic", "EXTERNAL_ID_NOT_ENFORCED"), failure("deterministic", "EXTERNAL_ID_NOT_ENFORCED"), nil)
	outcome, err := clock.policy(2*time.Minute).run(t.Context(), call)
	if err == nil || *calls != 2 || outcome.timedOut {
		t.Fatalf("got %v after %d calls, timed out %t", err, *calls, outcome.timedOut)
	}
}

func TestVerificationKeepsGoingWhenTheDeterministicAnswerChanges(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	call, calls := answers(failure("deterministic", "ACCOUNT_ID_MISMATCH"), failure("deterministic", "EXTERNAL_ID_NOT_ENFORCED"))
	if _, err := clock.policy(2*time.Minute).run(t.Context(), call); err != nil || *calls != 3 {
		t.Fatalf("got %v after %d calls", err, *calls)
	}
}

func TestVerificationDoesNotRetryOtherErrors(t *testing.T) {
	clock := &fakeClock{now: time.Unix(0, 0)}
	other := &client.APIError{Status: 409, Code: "already_exists"}
	call, calls := answers(other)
	if _, err := clock.policy(2*time.Minute).run(t.Context(), call); !errors.Is(err, other) || *calls != 1 {
		t.Fatalf("got %v after %d calls", err, *calls)
	}
}

func TestVerificationStopsAtTheContextDeadline(t *testing.T) {
	clock := &fakeClock{now: time.Now()}
	ctx, cancel := context.WithDeadline(t.Context(), clock.now.Add(10*time.Second))
	defer cancel()
	errs := make([]error, 50)
	for i := range errs {
		errs[i] = failure("propagation", "AccessDenied")
	}
	call, calls := answers(errs...)
	outcome, err := clock.policy(2*time.Minute).run(ctx, call)
	if err == nil || !outcome.timedOut || *calls != 2 {
		t.Fatalf("got %v after %d calls, timed out %t", err, *calls, outcome.timedOut)
	}
}
