package provider

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
)

const (
	deploymentsWriteScope  = "deployments:write"
	integrationsWriteScope = "integrations:write"
	planOnlyEnv            = "ACT_PLAN_ONLY"
)

type plannedWrite struct {
	data  *ProviderData
	scope string
	req   resource.ModifyPlanRequest
	resp  *resource.ModifyPlanResponse
}

func requireWriteScope(w plannedWrite) {
	if w.data == nil || w.data.Whoami == nil || slices.Contains(w.data.Whoami.Scopes, w.scope) {
		return
	}
	action, writes := plannedAction(w.req, w.resp)
	if !writes {
		return
	}
	summary := "The Act API key cannot apply this change"
	detail := fmt.Sprintf(
		"This plan %s the resource, which needs the %s scope. The API key %q holds %s. Run the apply with an API key whose access is Read and write. To plan with a read-only key on purpose, set %s=true and this stays a warning.",
		action, w.scope, w.data.Whoami.Principal.Name, heldScopes(w.data.Whoami.Scopes), planOnlyEnv,
	)
	if w.data.PlanOnly {
		w.resp.Diagnostics.AddWarning(summary, detail)
		return
	}
	w.resp.Diagnostics.AddError(summary, detail)
}

func plannedAction(req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) (string, bool) {
	switch {
	case req.State.Raw.IsNull() && req.Plan.Raw.IsNull():
		return "", false
	case req.State.Raw.IsNull():
		return "creates", true
	case req.Plan.Raw.IsNull():
		return "destroys", true
	case resp.Plan.Raw.Equal(req.State.Raw):
		return "", false
	default:
		return "changes", true
	}
}

func heldScopes(scopes []string) string {
	if len(scopes) == 0 {
		return "no scopes"
	}
	return strings.Join(scopes, ", ")
}
