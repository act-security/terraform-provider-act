package provider

import (
	"context"
	"testing"
	"time"
)

func FastVerification(t testing.TB) {
	t.Helper()
	previous := awsVerification
	awsVerification.base = time.Millisecond
	awsVerification.max = 5 * time.Millisecond
	awsVerification.sleep = func(context.Context, time.Duration) error { return nil }
	t.Cleanup(func() { awsVerification = previous })
}
