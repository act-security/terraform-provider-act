package provider

import (
	"fmt"
	"slices"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

const (
	deploymentsWriteScope  = "deployments:write"
	integrationsWriteScope = "integrations:write"
	missingWriteScopeTitle = "The Act API key cannot apply this change"
)

type writeAccess struct {
	scope    string
	typeName string
}

func (w writeAccess) warnAtPlan(data *ProviderData, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	action, writes := plannedAction(req, resp)
	if !writes || w.held(data) {
		return
	}
	resp.Diagnostics.AddWarning(
		missingWriteScopeTitle,
		fmt.Sprintf("This plan %s, which %s. The apply stops before it calls the Act API unless it runs with %s.", w.change(action), w.lack(data), w.keyThatCan()),
	)
}

func (w writeAccess) refuseAtApply(data *ProviderData, action string, diags *diag.Diagnostics) bool {
	if w.held(data) {
		return false
	}
	diags.AddError(
		missingWriteScopeTitle,
		fmt.Sprintf("This apply %s, which %s. Nothing was sent to Act. Apply with %s.", w.change(action), w.lack(data), w.keyThatCan()),
	)
	return true
}

func (w writeAccess) held(data *ProviderData) bool {
	return data == nil || data.Whoami == nil || slices.Contains(data.Whoami.Scopes, w.scope)
}

func (w writeAccess) change(action string) string {
	return fmt.Sprintf("%s %s", action, w.typeName)
}

func (w writeAccess) keyThatCan() string {
	return fmt.Sprintf("a Read and write API key whose role grants %s", w.scope)
}

func (w writeAccess) lack(data *ProviderData) string {
	return fmt.Sprintf("needs the %s scope. The API key %q holds %s", w.scope, data.Whoami.Principal.Name, heldScopes(data.Whoami.Scopes))
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
