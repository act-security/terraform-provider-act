package provider

import (
	"context"
	"testing"
	"time"
)

func FastVerification(t testing.TB) {
	t.Helper()
	for _, policy := range []*verificationPolicy{&awsVerification, &azureVerification} {
		previous := *policy
		policy.settle = 0
		policy.base = time.Millisecond
		policy.max = 5 * time.Millisecond
		policy.sleep = func(context.Context, time.Duration) error { return nil }
		t.Cleanup(func() { *policy = previous })
	}
}
