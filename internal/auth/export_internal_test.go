//go:build actinternal

package auth

func SetInternalOrigins(sts, api string) func() {
	previousSTS, previousAPI := internalSTSOrigins, internalAPIOrigins
	internalSTSOrigins, internalAPIOrigins = nonEmpty(sts), nonEmpty(api)
	return func() { internalSTSOrigins, internalAPIOrigins = previousSTS, previousAPI }
}
