package auth

import (
	"fmt"
	"net"
	"net/url"
	"slices"
	"strings"
)

type Endpoint struct {
	Origin string
	Unsafe bool
}

func ResolveEndpoint(override string) (Endpoint, error) {
	if override == "" {
		return Endpoint{Origin: ProductionSTSOrigin}, nil
	}
	origin, err := CanonicalOrigin(override)
	if err != nil {
		return Endpoint{}, fmt.Errorf("ACT_ENDPOINT: %w", err)
	}
	if slices.Contains(STSOrigins(), origin) {
		return Endpoint{Origin: origin}, nil
	}
	if allowUnsafeEndpoint() && isLoopbackOrigin(origin) {
		return Endpoint{Origin: origin, Unsafe: true}, nil
	}
	return Endpoint{}, fmt.Errorf("ACT_ENDPOINT %q is not an Act STS origin this build accepts", origin)
}

func (e Endpoint) apiOriginAllowed(origin string) bool {
	if APIOriginAllowed(origin) {
		return true
	}
	return e.Unsafe && isLoopbackOrigin(origin)
}

func CanonicalOrigin(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", fmt.Errorf("%q must use https", raw)
	}
	if u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("%q must be an origin: scheme and host only", raw)
	}
	return u.Scheme + "://" + strings.ToLower(u.Host), nil
}

func isLoopbackOrigin(origin string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	host := u.Hostname()
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
