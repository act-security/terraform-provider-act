package fakeapi

import (
	"net/http"
	"regexp"
	"strings"
)

var deploymentSubresource = regexp.MustCompile(`^/v1/deployments/[0-9a-f-]{36}/[a-z-]+$`)

type router struct {
	byID  *http.ServeMux
	other *http.ServeMux
}

func newRouter() *router {
	return &router{byID: http.NewServeMux(), other: http.NewServeMux()}
}

func (r *router) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	if strings.Contains(pattern, "/v1/deployments/{id}/") {
		r.byID.HandleFunc(pattern, handler)
		return
	}
	r.other.HandleFunc(pattern, handler)
}

func (r *router) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if deploymentSubresource.MatchString(req.URL.Path) && !strings.HasPrefix(req.URL.Path, "/v1/deployments/aws/") {
		r.byID.ServeHTTP(w, req)
		return
	}
	r.other.ServeHTTP(w, req)
}
