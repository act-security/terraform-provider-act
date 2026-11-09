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

type slackSecret struct {
	writeOnly bool
	ephemeral bool
	version   int
}

func slackConfig(secret slackSecret) string {
	ephemeral := ""
	if secret.ephemeral {
		ephemeral = "  ephemeral = true\n"
	}
	variable := "variable \"slack_bot_token\" {\n  type      = string\n  sensitive = true\n" + ephemeral + "}\n"
	argument := "  bot_token = var.slack_bot_token\n"
	if secret.writeOnly {
		argument = fmt.Sprintf("  bot_token_wo         = var.slack_bot_token\n  bot_token_wo_version = %d\n", secret.version)
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
resource "act_slack_integration" "this" {
%s}

output "integration_id" {
  value = act_slack_integration.this.id
}
`, h.version, variable, argument)
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
	w := startWorld(t, fakeapi.DefaultConfig())
	first, second := "xoxb-e2e-first-token", "xoxb-e2e-second-token"
	probe := newWorkspace(t, w, nil)
	writeOnly := terraformVersion(t, probe).GreaterThanOrEqual(version.Must(version.NewVersion("1.11.0")))

	if !writeOnly {
		ws := newWorkspaceWith(t, w, map[string]string{"TF_VAR_slack_bot_token": first}, slackConfig(slackSecret{writeOnly: true, version: 1}))
		ws.expectPlanError("only supported in Terraform 1.11")

		ws = newWorkspaceWith(t, w, map[string]string{"TF_VAR_slack_bot_token": first}, slackConfig(slackSecret{}))
		ws.must("apply", "-input=false", "-auto-approve", "-no-color")
		id := ws.outputs()["integration_id"]
		if got, _ := w.fake.IntegrationSecret(id); got != first {
			t.Fatalf("Act holds %q, want the configured token", got)
		}
		ws.must("destroy", "-input=false", "-auto-approve", "-no-color")
		return
	}

	ws := newWorkspaceWith(t, w, map[string]string{"TF_VAR_slack_bot_token": first}, slackConfig(slackSecret{writeOnly: true, ephemeral: true, version: 1}))
	ws.must("apply", "-input=false", "-auto-approve", "-no-color")
	id := ws.outputs()["integration_id"]
	if got, _ := w.fake.IntegrationSecret(id); got != first {
		t.Fatalf("Act holds %q, want the configured token", got)
	}
	if strings.Contains(stateFile(t, ws), first) {
		t.Fatal("the write-only token reached the state file")
	}

	rotated := newWorkspaceWith(t, w, map[string]string{"TF_VAR_slack_bot_token": second}, slackConfig(slackSecret{writeOnly: true, ephemeral: true, version: 1}))
	rotated.dir = ws.dir
	rotated.writeConfig(slackConfig(slackSecret{writeOnly: true, ephemeral: true, version: 2}))
	rotated.must("apply", "-input=false", "-auto-approve", "-no-color")
	if got := rotated.outputs()["integration_id"]; got != id {
		t.Fatalf("rotation replaced the integration: %s, then %s", id, got)
	}
	if got, _ := w.fake.IntegrationSecret(id); got != second {
		t.Fatalf("Act holds %q after the rotation", got)
	}
	if state := stateFile(t, rotated); strings.Contains(state, first) || strings.Contains(state, second) {
		t.Fatal("a write-only token reached the state file")
	}
	rotated.must("destroy", "-input=false", "-auto-approve", "-no-color")
	if refused := w.proxy.Refused(); len(refused) > 0 {
		t.Errorf("the provider tried to reach hosts other than Act: %v", refused)
	}
}
