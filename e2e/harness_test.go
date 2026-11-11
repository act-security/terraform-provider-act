//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-version"
	install "github.com/hashicorp/hc-install"
	"github.com/hashicorp/hc-install/product"
	"github.com/hashicorp/hc-install/releases"
	"github.com/hashicorp/hc-install/src"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

const providerRepo = "terraform-provider-act"

var mirrorHosts = []string{"registry.terraform.io"}

type harness struct {
	root      string
	tf        string
	version   string
	cliConfig string
	pki       *pki
	untrusted *pki
}

var h harness

func TestMain(m *testing.M) {
	code, err := run(m)
	if err != nil {
		log.Printf("e2e setup: %v", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	root, err := os.MkdirTemp("", "act-e2e-")
	if err != nil {
		return 0, err
	}
	defer func() {
		if cleanupErr := os.RemoveAll(root); cleanupErr != nil {
			log.Printf("e2e cleanup: %v", cleanupErr)
		}
	}()
	h.root = root

	dist, err := filepath.Abs(envOr("E2E_DIST", filepath.Join("..", "dist")))
	if err != nil {
		return 0, err
	}
	if h.version, err = distVersion(dist); err != nil {
		return 0, err
	}
	zipName := fmt.Sprintf("%s_%s_%s_%s.zip", providerRepo, h.version, runtime.GOOS, runtime.GOARCH)
	if err = buildMirror(filepath.Join(dist, zipName), filepath.Join(root, "mirror"), zipName); err != nil {
		return 0, err
	}
	h.cliConfig = filepath.Join(root, "terraformrc")
	if err = writeCLIConfig(h.cliConfig, filepath.Join(root, "mirror")); err != nil {
		return 0, err
	}
	if h.tf, err = resolveTerraform(filepath.Join(root, "bin")); err != nil {
		return 0, err
	}
	if h.pki, err = newPKI(root, "ca"); err != nil {
		return 0, err
	}
	if h.untrusted, err = newPKI(root, "untrusted-ca"); err != nil {
		return 0, err
	}
	log.Printf("e2e: provider %s (%s/%s) from %s, CLI %s", h.version, runtime.GOOS, runtime.GOARCH, dist, h.tf)
	return m.Run(), nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func distVersion(dist string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dist, "metadata.json"))
	if err != nil {
		return "", fmt.Errorf("reading the goreleaser metadata (run make rc first): %w", err)
	}
	var meta struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		return "", fmt.Errorf("parsing %s/metadata.json: %w", dist, err)
	}
	if meta.Version == "" {
		return "", fmt.Errorf("%s/metadata.json has no version", dist)
	}
	return meta.Version, nil
}

func buildMirror(zip, mirror, zipName string) error {
	data, err := os.ReadFile(filepath.Clean(zip))
	if err != nil {
		return fmt.Errorf("reading the provider zip: %w", err)
	}
	for _, host := range mirrorHosts {
		dir := filepath.Join(mirror, host, "act-security", "act")
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dir, zipName), data, 0o600); err != nil {
			return err
		}
	}
	return nil
}

func writeCLIConfig(path, mirror string) error {
	includes := make([]string, 0, len(mirrorHosts))
	for _, host := range mirrorHosts {
		includes = append(includes, fmt.Sprintf("%q", host+"/act-security/act"))
	}
	config := fmt.Sprintf(`provider_installation {
  filesystem_mirror {
    path    = %q
    include = [%s]
  }
}
`, filepath.ToSlash(mirror), strings.Join(includes, ", "))
	return os.WriteFile(path, []byte(config), 0o600)
}

func resolveTerraform(installDir string) (string, error) {
	if v := os.Getenv("E2E_TERRAFORM_VERSION"); v != "" {
		want, err := version.NewVersion(v)
		if err != nil {
			return "", fmt.Errorf("E2E_TERRAFORM_VERSION: %w", err)
		}
		if err := os.MkdirAll(installDir, 0o750); err != nil {
			return "", err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		return install.NewInstaller().Ensure(ctx, []src.Source{&releases.ExactVersion{
			Product:    product.Terraform,
			Version:    want,
			InstallDir: installDir,
		}})
	}
	p, err := exec.LookPath(envOr("E2E_TF", "terraform"))
	if err != nil {
		return "", errors.New("no CLI to test with: set E2E_TF to a terraform binary, or E2E_TERRAFORM_VERSION to download one")
	}
	return p, nil
}

func requireLinux(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the provider trusts the throwaway CA through SSL_CERT_FILE, which Go reads only on Linux")
	}
}

func identityConfig() string {
	return fmt.Sprintf(`terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "= %s"
    }
  }
}

provider "act" {}

data "act_current_identity" "this" {}

output "tenant_id" {
  value = data.act_current_identity.this.tenant_id
}

output "tenant_display_name" {
  value = data.act_current_identity.this.tenant_display_name
}

output "region" {
  value = data.act_current_identity.this.region
}
`, h.version)
}

type workspace struct {
	t   *testing.T
	dir string
	env []string
}

func newWorkspace(t *testing.T, w *world, overrides map[string]string) *workspace {
	t.Helper()
	return newWorkspaceWith(t, w, overrides, identityConfig())
}

func newWorkspaceWith(t *testing.T, w *world, overrides map[string]string, config string) *workspace {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.tf"), []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{
		"TF_CLI_CONFIG_FILE": h.cliConfig,
		"TF_IN_AUTOMATION":   "1",
		"CHECKPOINT_DISABLE": "1",
		"SSL_CERT_FILE":      h.pki.caFile,
		"ACT_TENANT_ID":      fakeapi.DefaultTenantID,
		"ACT_CLIENT_ID":      fakeapi.DefaultClientID,
		"ACT_CLIENT_SECRET":  fakeapi.DefaultClientSecret,
	}
	if w != nil {
		vars["HTTPS_PROXY"] = w.proxy.url
	}
	for k, v := range overrides {
		vars[k] = v
	}
	env := make([]string, 0, len(vars))
	for _, kv := range os.Environ() {
		if !inherited(strings.SplitN(kv, "=", 2)[0]) {
			continue
		}
		env = append(env, kv)
	}
	for k, v := range vars {
		env = append(env, k+"="+v)
	}
	ws := &workspace{t: t, dir: dir, env: env}
	ws.must("init", "-input=false", "-no-color")
	return ws
}

func inherited(name string) bool {
	upper := strings.ToUpper(name)
	if strings.HasPrefix(upper, "ACT_") || strings.HasPrefix(upper, "TF_") {
		return false
	}
	switch upper {
	case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR":
		return false
	}
	return true
}

func (ws *workspace) writeConfig(config string) {
	ws.t.Helper()
	if err := os.WriteFile(filepath.Join(ws.dir, "main.tf"), []byte(config), 0o600); err != nil {
		ws.t.Fatal(err)
	}
}

func (ws *workspace) run(args ...string) (stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(ws.t.Context(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, h.tf, args...)
	cmd.Dir = ws.dir
	cmd.Env = ws.env
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err = cmd.Run()
	return out.String(), errOut.String(), err
}

func (ws *workspace) must(args ...string) string {
	ws.t.Helper()
	out, errOut, err := ws.run(args...)
	if err != nil {
		ws.t.Fatalf("%s %s: %v\nstdout:\n%s\nstderr:\n%s", filepath.Base(h.tf), strings.Join(args, " "), err, out, errOut)
	}
	return out
}

func (ws *workspace) expectPlanError(want string) {
	ws.t.Helper()
	out, errOut, err := ws.run("plan", "-input=false", "-json")
	if err == nil {
		ws.t.Fatalf("plan succeeded, want an error mentioning %q\nstdout:\n%s", want, out)
	}
	var seen []string
	scanner := bufio.NewScanner(strings.NewReader(out))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		var line struct {
			Diagnostic *struct {
				Severity string `json:"severity"`
				Summary  string `json:"summary"`
				Detail   string `json:"detail"`
			} `json:"diagnostic"`
		}
		if json.Unmarshal(scanner.Bytes(), &line) != nil || line.Diagnostic == nil || line.Diagnostic.Severity != "error" {
			continue
		}
		text := line.Diagnostic.Summary + ": " + line.Diagnostic.Detail
		if strings.Contains(text, want) {
			return
		}
		seen = append(seen, text)
	}
	ws.t.Fatalf("plan failed without an error mentioning %q\nerrors: %q\nstderr:\n%s", want, seen, errOut)
}

func (ws *workspace) outputs() map[string]string {
	ws.t.Helper()
	var raw map[string]struct {
		Value any `json:"value"`
	}
	if err := json.Unmarshal([]byte(ws.must("output", "-json")), &raw); err != nil {
		ws.t.Fatalf("parsing the outputs: %v", err)
	}
	got := make(map[string]string, len(raw))
	for k, v := range raw {
		got[k] = fmt.Sprint(v.Value)
	}
	return got
}
