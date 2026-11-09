//go:build e2e

package e2e

import (
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

func TestInstallsFromTheMirror(t *testing.T) {
	ws := newWorkspace(t, nil, nil)

	lock, err := os.ReadFile(filepath.Join(ws.dir, ".terraform.lock.hcl"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(lock), `version     = "`+h.version+`"`) {
		t.Fatalf("the lock file does not pin %s:\n%s", h.version, lock)
	}

	var v struct {
		ProviderSelections map[string]string `json:"provider_selections"`
	}
	if err := json.Unmarshal([]byte(ws.must("version", "-json")), &v); err != nil {
		t.Fatal(err)
	}
	selected := ""
	for addr, ver := range v.ProviderSelections {
		if strings.HasSuffix(addr, "/act-security/act") {
			selected = ver
		}
	}
	if selected != h.version {
		t.Fatalf("selected act provider %q, want %q (selections %v)", selected, h.version, v.ProviderSelections)
	}

	ws.must("validate", "-no-color")

	var schema struct {
		ProviderSchemas map[string]struct {
			Provider struct {
				Block struct {
					Attributes map[string]json.RawMessage `json:"attributes"`
				} `json:"block"`
			} `json:"provider"`
			DataSourceSchemas map[string]json.RawMessage `json:"data_source_schemas"`
		} `json:"provider_schemas"`
	}
	if err := json.Unmarshal([]byte(ws.must("providers", "schema", "-json")), &schema); err != nil {
		t.Fatal(err)
	}
	found := false
	for addr, s := range schema.ProviderSchemas {
		if !strings.HasSuffix(addr, "/act-security/act") {
			continue
		}
		found = true
		for _, attr := range []string{"tenant_id", "client_id", "client_secret"} {
			if _, ok := s.Provider.Block.Attributes[attr]; !ok {
				t.Errorf("the provider schema has no %s", attr)
			}
		}
		if _, ok := s.DataSourceSchemas["act_current_identity"]; !ok {
			t.Error("the provider has no act_current_identity data source")
		}
	}
	if !found {
		t.Fatal("the schema output has no act-security/act provider")
	}
}

func TestReadsTheIdentity(t *testing.T) {
	requireLinux(t)
	w := startWorld(t, fakeapi.DefaultConfig())
	ws := newWorkspace(t, w, nil)

	ws.must("apply", "-input=false", "-auto-approve", "-no-color")
	want := map[string]string{
		"tenant_id":           fakeapi.DefaultTenantID,
		"tenant_display_name": fakeapi.DefaultTenantDisplayName,
		"region":              fakeapi.DefaultRegion,
	}
	got := ws.outputs()
	for k, v := range want {
		if got[k] != v {
			t.Errorf("output %s = %q, want %q", k, got[k], v)
		}
	}

	_, _, err := ws.run("plan", "-input=false", "-detailed-exitcode", "-no-color")
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && exit.ExitCode() == 2 {
			t.Fatal("a second plan wants changes; reading the identity must be stable")
		}
		t.Fatalf("second plan: %v", err)
	}
	ws.must("destroy", "-input=false", "-auto-approve", "-no-color")

	requests := w.fake.Recorder().Requests()
	counts := map[string]int{}
	for _, r := range requests {
		counts[r.Origin+" "+r.Method+" "+r.Path]++
		if !strings.HasPrefix(r.UserAgent, "terraform-provider-act/"+h.version+" ") {
			t.Errorf("%s %s sent User-Agent %q, want terraform-provider-act/%s", r.Method, r.Path, r.UserAgent, h.version)
		}
		if r.Status != http.StatusOK {
			t.Errorf("%s %s got %d", r.Method, r.Path, r.Status)
		}
	}
	for _, call := range []string{
		fakeapi.OriginSTS + " POST /oidc/oauth2/token",
		fakeapi.OriginSTS + " GET /oidc/tenants/" + fakeapi.DefaultTenantID,
		fakeapi.OriginAPI + " GET /v1/whoami",
	} {
		if counts[call] == 0 {
			t.Errorf("the provider never called %s (calls: %v)", call, counts)
		}
	}
	if refused := w.proxy.Refused(); len(refused) > 0 {
		t.Errorf("the provider tried to reach hosts other than Act: %v", refused)
	}
}

func TestReadsTheIdentityWithoutTenantID(t *testing.T) {
	requireLinux(t)
	w := startWorld(t, fakeapi.DefaultConfig())
	ws := newWorkspace(t, w, map[string]string{"ACT_TENANT_ID": ""})

	ws.must("apply", "-input=false", "-auto-approve", "-no-color")
	if got := ws.outputs()["tenant_id"]; got != fakeapi.DefaultTenantID {
		t.Fatalf("output tenant_id = %q, want %q from the token", got, fakeapi.DefaultTenantID)
	}
	if refused := w.proxy.Refused(); len(refused) > 0 {
		t.Errorf("the provider tried to reach hosts other than Act: %v", refused)
	}
}

func TestFailsClosed(t *testing.T) {
	requireLinux(t)
	offAllowList, err := json.Marshal(map[string]string{
		"tenantId":     fakeapi.DefaultTenantID,
		"region":       fakeapi.DefaultRegion,
		"publicApiUrl": "https://api.evil.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		mutate     func(*fakeapi.Config)
		env        map[string]string
		want       string
		noRequests bool
	}{
		{
			name: "wrong client secret",
			env:  map[string]string{"ACT_CLIENT_SECRET": "wrong"},
			want: "rejected the client_id and client_secret",
		},
		{
			name: "tenant the key is not bound to",
			env:  map[string]string{"ACT_TENANT_ID": "00000000-0000-4000-8000-000000000002"},
			want: "not bound to this tenant_id",
		},
		{
			name:   "public API not available yet",
			mutate: func(c *fakeapi.Config) { c.PublicAPIUnavailable = true },
			want:   "not available for this tenant yet",
		},
		{
			name: "public API URL off the allow-list",
			mutate: func(c *fakeapi.Config) {
				c.Script = fakeapi.Script{"GET /oidc/tenants/" + fakeapi.DefaultTenantID: {{Status: http.StatusOK, Body: offAllowList}}}
			},
			want: "which this build does not accept",
		},
		{
			name:       "loopback STS even with the unsafe flag",
			env:        map[string]string{"ACT_ENDPOINT": "http://127.0.0.1:8787", "ACT_ALLOW_UNSAFE_ENDPOINT": "1"},
			want:       "is not an Act STS origin this build accepts",
			noRequests: true,
		},
		{
			name:       "certificate from an untrusted CA",
			env:        map[string]string{"SSL_CERT_FILE": h.untrusted.caFile},
			want:       "x509:",
			noRequests: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := fakeapi.DefaultConfig()
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			w := startWorld(t, cfg)
			ws := newWorkspace(t, w, tt.env)
			ws.expectPlanError(tt.want)
			requests := w.fake.Recorder().Requests()
			for _, r := range requests {
				if r.Origin == fakeapi.OriginAPI {
					t.Errorf("the provider called the API (%s %s) after authentication failed", r.Method, r.Path)
				}
			}
			if tt.noRequests && len(requests) > 0 {
				t.Errorf("the provider reached the fake STS: %v", requests)
			}
		})
	}
}
