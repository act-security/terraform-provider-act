package fakeapi

import "sync"

const (
	OriginSTS = "sts"
	OriginAPI = "api"
)

type Request struct {
	Origin    string
	Method    string
	Path      string
	Status    int
	UserAgent string
}

type Recorder struct {
	mu       sync.Mutex
	requests []Request
}

func (r *Recorder) add(req Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, req)
}

func (r *Recorder) Requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Request(nil), r.requests...)
}
