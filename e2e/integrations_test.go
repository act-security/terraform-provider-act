//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/go-version"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

type integrationUnderTest struct {
	resourceType string
	secretAttr   string
	settings     string
	first        string
	second       string
}

var integrationsUnderTest = []integrationUnderTest{
	{
		resourceType: "act_slack_integration",
		secretAttr:   "bot_token",
		first:        "xoxb-e2e-first-token",
		second:       "xoxb-e2e-second-token",
	},
	{
		resourceType: "act_cortex_cloud_integration",
		secretAttr:   "api_key",
		settings:     "  api_url        = \"https://api-acme.xdr.us.paloaltonetworks.com\"\n  api_key_id     = \"7\"\n  security_level = \"advanced\"\n",
		first:        "e2e-first-cortex-key",
		second:       "e2e-second-cortex-key",
	},
}

type secretMode struct {
	writeOnly bool
	ephemeral bool
	version   int
}

func (k integrationUnderTest) config(secret secretMode) string {
	ephemeral := ""
	if secret.ephemeral {
		ephemeral = "  ephemeral = true\n"
	}
	variable := "variable \"secret\" {\n  type      = string\n  sensitive = true\n" + ephemeral + "}\n"
	argument := fmt.Sprintf("  %s = var.secret\n", k.secretAttr)
	if secret.writeOnly {
		argument = fmt.Sprintf("  %s_wo         = var.secret\n  %s_wo_version = %d\n", k.secretAttr, k.secretAttr, secret.version)
	}
	return fmt.Sprintf(`terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "= %s"
    }
  }
}

provider "act" {}

%s
resource %q "this" {
%s%s}

output "integration_id" {
  value = %s.this.id
}
`, h.version, variable, k.resourceType, k.settings, argument, k.resourceType)
}

func terraformVersion(t *testing.T, ws *workspace) *version.Version {
	t.Helper()
	var v struct {
		TerraformVersion string `json:"terraform_version"`
	}
	if err := json.Unmarshal([]byte(ws.must("version", "-json")), &v); err != nil {
		t.Fatal(err)
	}
	parsed, err := version.NewVersion(v.TerraformVersion)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func stateFile(t *testing.T, ws *workspace) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(ws.dir, "terraform.tfstate"))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestManagesAnIntegrationSecretTheWayTheCLISupports(t *testing.T) {
	requireLinux(t)
	for _, kind := range integrationsUnderTest {
		t.Run(kind.resourceType, func(t *testing.T) {
			managesTheSecretTheWayTheCLISupports(t, kind)
		})
	}
}

func managesTheSecretTheWayTheCLISupports(t *testing.T, kind integrationUnderTest) {
	t.Helper()
	w := startWorld(t, fakeapi.DefaultConfig())
	first, second := kind.first, kind.second
	probe := newWorkspace(t, w, nil)
	writeOnly := terraformVersion(t, probe).GreaterThanOrEqual(version.Must(version.NewVersion("1.11.0")))

	if !writeOnly {
		ws := newWorkspaceWith(t, w, map[string]string{"TF_VAR_secret": first}, kind.config(secretMode{writeOnly: true, version: 1}))
		ws.expectPlanError("only supported in Terraform 1.11")

		ws = newWorkspaceWith(t, w, map[string]string{"TF_VAR_secret": first}, kind.config(secretMode{}))
		ws.must("apply", "-input=false", "-auto-approve", "-no-color")
		id := ws.outputs()["integration_id"]
		if got, _ := w.fake.IntegrationSecret(id); got != first {
			t.Fatalf("Act holds %q, want the configured secret", got)
		}
		ws.must("destroy", "-input=false", "-auto-approve", "-no-color")
		return
	}

	ws := newWorkspaceWith(t, w, map[string]string{"TF_VAR_secret": first}, kind.config(secretMode{writeOnly: true, ephemeral: true, version: 1}))
	ws.must("apply", "-input=false", "-auto-approve", "-no-color")
	id := ws.outputs()["integration_id"]
	if got, _ := w.fake.IntegrationSecret(id); got != first {
		t.Fatalf("Act holds %q, want the configured secret", got)
	}
	if strings.Contains(stateFile(t, ws), first) {
		t.Fatal("the write-only secret reached the state file")
	}

	rotated := newWorkspaceWith(t, w, map[string]string{"TF_VAR_secret": second}, kind.config(secretMode{writeOnly: true, ephemeral: true, version: 1}))
	rotated.dir = ws.dir
	rotated.writeConfig(kind.config(secretMode{writeOnly: true, ephemeral: true, version: 2}))
	rotated.must("apply", "-input=false", "-auto-approve", "-no-color")
	if got := rotated.outputs()["integration_id"]; got != id {
		t.Fatalf("rotation replaced the integration: %s, then %s", id, got)
	}
	if got, _ := w.fake.IntegrationSecret(id); got != second {
		t.Fatalf("Act holds %q after the rotation", got)
	}
	if state := stateFile(t, rotated); strings.Contains(state, first) || strings.Contains(state, second) {
		t.Fatal("a write-only secret reached the state file")
	}
	rotated.must("destroy", "-input=false", "-auto-approve", "-no-color")
	if refused := w.proxy.Refused(); len(refused) > 0 {
		t.Errorf("the provider tried to reach hosts other than Act: %v", refused)
	}
}
