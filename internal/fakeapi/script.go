package fakeapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type ScriptResponse struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    json.RawMessage   `json:"body,omitempty"`
}

type Script map[string][]ScriptResponse

func LoadScript(path string) (Script, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("reading the script: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s Script
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing the script %s: %w", path, err)
	}
	for key, responses := range s {
		for i, resp := range responses {
			if resp.Status < 100 || resp.Status > 599 {
				return nil, fmt.Errorf("script %q response %d: status %d is not an HTTP status", key, i, resp.Status)
			}
		}
	}
	return s, nil
}

type scriptQueue struct {
	mu     sync.Mutex
	queues Script
}

func newScriptQueue(s Script) *scriptQueue {
	q := &scriptQueue{queues: Script{}}
	for key, responses := range s {
		q.queues[key] = append([]ScriptResponse(nil), responses...)
	}
	return q
}

func (q *scriptQueue) next(key string) (ScriptResponse, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	queue := q.queues[key]
	if len(queue) == 0 {
		return ScriptResponse{}, false
	}
	q.queues[key] = queue[1:]
	return queue[0], true
}

func (s ScriptResponse) write(w http.ResponseWriter) {
	for k, v := range s.Headers {
		w.Header().Set(k, v)
	}
	if len(s.Body) > 0 && w.Header().Get("Content-Type") == "" {
		w.Header().Set("Content-Type", "application/json")
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(s.Body)))
	w.WriteHeader(s.Status)
	if _, err := w.Write(s.Body); err != nil {
		return
	}
}
