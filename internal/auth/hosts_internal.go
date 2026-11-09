//go:build actinternal

package auth

import "os"

const unsafeEndpointEnv = "ACT_ALLOW_UNSAFE_ENDPOINT"

var (
	internalSTSOrigin  string
	internalAPIOrigin  string
	internalSTSOrigins = nonEmpty(internalSTSOrigin)
	internalAPIOrigins = nonEmpty(internalAPIOrigin)
)

func nonEmpty(origin string) []string {
	if origin == "" {
		return nil
	}
	return []string{origin}
}

func allowUnsafeEndpoint() bool {
	return os.Getenv(unsafeEndpointEnv) == "1"
}
