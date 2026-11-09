//go:build !actinternal

package auth

var (
	internalSTSOrigins []string
	internalAPIOrigins []string
)

func allowUnsafeEndpoint() bool {
	return false
}
