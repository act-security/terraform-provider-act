package auth

import (
	"regexp"
	"slices"
)

const (
	ProductionSTSOrigin = "https://auth.act.security"
	DiscoveryPath       = "/oidc/tenants"
)

var cellAPIOrigin = regexp.MustCompile(`^https://api\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.act\.security$`)

func STSOrigins() []string {
	return append([]string{ProductionSTSOrigin}, internalSTSOrigins...)
}

func APIOriginAllowed(origin string) bool {
	return cellAPIOrigin.MatchString(origin) || slices.Contains(internalAPIOrigins, origin)
}

func DiscoveryAudience(stsOrigin string) string {
	return stsOrigin + DiscoveryPath
}
