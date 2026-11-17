package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	defaultAzureDeploymentTimeout = 12 * time.Minute
	azureDeploymentTitle          = "Azure"
	azureSubscriptionImport       = "subscription"
	azureManagementGroupImport    = "management-group"
)

var azureManagementGroupPattern = regexp.MustCompile(`^[A-Za-z0-9_().-]{1,90}$`)

type azureDeploymentModel struct {
	ID                 types.String   `tfsdk:"id"`
	DeploymentID       types.String   `tfsdk:"deployment_id"`
	SubscriptionID     types.String   `tfsdk:"subscription_id"`
	ManagementGroupID  types.String   `tfsdk:"management_group_id"`
	AzureTenantID      types.String   `tfsdk:"azure_tenant_id"`
	ServicePrincipalID types.String   `tfsdk:"service_principal_id"`
	IncludeEntraID     types.Bool     `tfsdk:"include_entra_id"`
	Name               types.String   `tfsdk:"name"`
	Tags               types.Map      `tfsdk:"tags"`
	DeploymentMethod   types.String   `tfsdk:"deployment_method"`
	DeletionProtection types.Bool     `tfsdk:"deletion_protection"`
	ReverifyOnFailure  types.Bool     `tfsdk:"reverify_on_failure"`
	Status             types.String   `tfsdk:"status"`
	ConsentURL         types.String   `tfsdk:"consent_url"`
	ErrorCode          types.String   `tfsdk:"error_code"`
	ErrorMessage       types.String   `tfsdk:"error_message"`
	UpdateAvailable    types.Bool     `tfsdk:"update_available"`
	DeployedVersion    types.String   `tfsdk:"deployed_version"`
	CreatedAt          types.String   `tfsdk:"created_at"`
	ConsoleURL         types.String   `tfsdk:"console_url"`
	CreatedVia         types.String   `tfsdk:"created_via"`
	Timeouts           timeouts.Value `tfsdk:"timeouts"`
}

var (
	_ resource.ResourceWithConfigure   = (*azureDeploymentResource)(nil)
	_ resource.ResourceWithImportState = (*azureDeploymentResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*azureDeploymentResource)(nil)
)

type azureDeploymentResource struct {
	data *ProviderData
}

func NewAzureDeploymentResource() resource.Resource {
	return &azureDeploymentResource{}
}

func (r *azureDeploymentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_deployment"
}

func (r *azureDeploymentResource) typeName() string {
	return "act_azure_deployment"
}

func (r *azureDeploymentResource) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Connects one Azure subscription or management group to Act through Act's multi-tenant app. Act checks the role assignments of its service principal before it stores anything. Until an Entra admin approves Act in the directory, the deployment is stored as `pending_consent` and the apply succeeds with a warning that carries the approval link.",
		Attributes:          azureDeploymentAttributes(),
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Update: true}),
		},
	}
}

func azureDeploymentAttributes() map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The deployment ID, equal to `deployment_id`.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"deployment_id": schema.StringAttribute{
			MarkdownDescription: "The deployment ID Act issued for this target, from `data.act_azure_onboarding_parameters`. Act rejects any other value. Changing it replaces the deployment.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"subscription_id": schema.StringAttribute{
			MarkdownDescription: "The Azure subscription to connect, a lowercase UUID. Set this or `management_group_id`. Changing it replaces the deployment.",
			Optional:            true,
			Validators: []validator.String{
				stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID"),
				stringvalidator.ExactlyOneOf(path.MatchRoot("management_group_id")),
			},
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"management_group_id": schema.StringAttribute{
			MarkdownDescription: "The Azure management group to connect, covering every subscription under it. Set this or `subscription_id`. Changing it replaces the deployment.",
			Optional:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(azureManagementGroupPattern, "must be an Azure management group ID: 1 to 90 letters, digits, or _ ( ) . -")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"azure_tenant_id": schema.StringAttribute{
			MarkdownDescription: "The Entra directory (Azure tenant) that owns the target, from `data.act_azure_onboarding_parameters`. Changing it replaces the deployment.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"service_principal_id": schema.StringAttribute{
			MarkdownDescription: "The object ID of Act's service principal in the directory. Pass it from the configuration that assigns its roles, such as an output of the Act module, so Terraform creates the role assignments first. Changing it updates the deployment in place and Act verifies it again.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
		},
		"include_entra_id": schema.BoolAttribute{
			MarkdownDescription: "When true, Act also reads Entra ID through Microsoft Graph. It needs the Graph app roles in `required_graph_app_role_ids` of the onboarding data source, and the approval then needs a Global Administrator or a Privileged Role Administrator. Defaults to `false`. Changing it updates the deployment in place and Act verifies it again.",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(false),
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name Act shows for the deployment, 1 to 64 characters. Act picks one when you leave it out. Changing it updates the deployment in place.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.LengthBetween(1, maxDeploymentNameLength)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"tags": schema.MapAttribute{
			MarkdownDescription: "Act tags for the deployment, at most 50. They are not Azure tags.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Map{
				mapvalidator.SizeAtMost(maxDeploymentTags),
				mapvalidator.KeysAre(stringvalidator.LengthBetween(1, maxTagKeyLength)),
				mapvalidator.ValueStringsAre(stringvalidator.LengthAtMost(maxTagValueLength)),
			},
		},
		"deployment_method": schema.StringAttribute{
			MarkdownDescription: "How the role assignments were made: `terraform` (default), `cli` or `manual`. Changing it replaces the deployment: on a protected deployment, set `deletion_protection = false` and apply that first, or the plan fails. When you import a deployment set up another way, set its method.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString(string(apigen.AzureDeploymentMethodTerraform)),
			Validators: []validator.String{stringvalidator.OneOf(
				string(apigen.AzureDeploymentMethodTerraform),
				string(apigen.AzureDeploymentMethodCli),
				string(apigen.AzureDeploymentMethodManual),
			)},
			PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"deletion_protection": schema.BoolAttribute{
			MarkdownDescription: "When true, Act refuses to delete the deployment and a plan that destroys it fails. Defaults to `true` for a management group and `false` for a subscription.",
			Optional:            true,
			Computed:            true,
			PlanModifiers:       []planmodifier.Bool{protectManagementGroupsByDefault{}},
		},
		"reverify_on_failure": schema.BoolAttribute{
			MarkdownDescription: "When the deployment is `failed`, plan a verification so the next apply makes it active again once the role assignments are fixed. It does nothing while the deployment is `pending_consent`. Defaults to `true`. Only the provider uses it.",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(true),
		},
		"status": schema.StringAttribute{
			MarkdownDescription: "`active` when Act can use the service principal, `pending_consent` until an Entra admin approves Act in the directory, `failed` when Act cannot use it.",
			Computed:            true,
		},
		"consent_url": schema.StringAttribute{
			MarkdownDescription: "The link an Entra admin opens once to approve Act. Set while the deployment is `pending_consent`, null otherwise.",
			Computed:            true,
		},
		"error_code":    schema.StringAttribute{MarkdownDescription: "Why the deployment failed. Null unless failed.", Computed: true},
		"error_message": schema.StringAttribute{MarkdownDescription: "What Act saw when the deployment failed. Null unless failed.", Computed: true},
		"update_available": schema.BoolAttribute{
			MarkdownDescription: "True when the role assignments are older than the version Act recommends.",
			Computed:            true,
		},
		"deployed_version": schema.StringAttribute{MarkdownDescription: "The version Act detected.", Computed: true},
		"created_at": schema.StringAttribute{
			MarkdownDescription: "When the deployment was created, in RFC 3339.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"console_url": schema.StringAttribute{
			MarkdownDescription: "The deployment's page in the Act console. Null when Act does not report one.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"created_via": schema.StringAttribute{
			MarkdownDescription: "`ui` or `api`. Null when Act does not know.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
	}
}

func (r *azureDeploymentResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "The provider passed data of an unexpected type.")
		return
	}
	r.data = data
}

func (r *azureDeploymentResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if !req.State.Raw.IsNull() && req.Plan.Raw.IsNull() {
		r.planDestroy(ctx, req.State, &resp.Diagnostics)
	}
	if !req.State.Raw.IsNull() && !req.Plan.Raw.IsNull() {
		r.planUpdate(ctx, req, resp)
	}
	r.writeAccess().warnAtPlan(r.data, req, resp)
}

func (r *azureDeploymentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "creates", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var model azureDeploymentModel
	if diags.Append(req.Plan.Get(ctx, &model)...); diags.HasError() {
		return
	}
	body := model.createBody(ctx, diags)
	ctx, cancel, ok := withAzureTimeout(ctx, model.Timeouts.Create, diags)
	if !ok {
		return
	}
	defer cancel()
	result, outcome, err := r.createVerified(ctx, body)
	if err != nil {
		r.errors().addWriteError(diags, writeFailure{action: createAction, target: model.targetLabel(), outcome: outcome, err: err})
		return
	}
	r.store(ctx, azureStored{model: &model, result: result, state: &resp.State, private: resp.Private, diags: diags})
	if model.Status.ValueString() == string(apigen.DeploymentStatusPendingConsent) {
		r.warnPendingConsent(&model, diags)
		return
	}
	diags.AddWarning("Act verified "+azureWording.credential, proofOfLife(connectionReport{target: model.targetLabel(), consoleURL: result.Deployment.ConsoleURL, outcome: outcome, wording: azureWording}))
}

func (r *azureDeploymentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	diags := &resp.Diagnostics
	var model azureDeploymentModel
	if diags.Append(req.State.Get(ctx, &model)...); diags.HasError() {
		return
	}
	result, err := r.data.Client.GetAzureDeployment(ctx, model.ID.ValueString())
	switch {
	case err != nil:
		diags.AddError("Reading the "+azureDeploymentTitle+" deployment failed", err.Error())
	case result == nil:
		resp.State.RemoveResource(ctx)
	default:
		if model.ReverifyOnFailure.IsNull() {
			model.ReverifyOnFailure = types.BoolValue(true)
		}
		r.store(ctx, azureStored{model: &model, result: result, state: &resp.State, private: resp.Private, diags: diags, quiet: true})
		r.reportStatus(&model, diags)
	}
}

func (r *azureDeploymentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "changes", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var next, prior azureDeploymentModel
	diags.Append(req.Plan.Get(ctx, &next)...)
	if diags.Append(req.State.Get(ctx, &prior)...); diags.HasError() {
		return
	}
	ctx, cancel, ok := withAzureTimeout(ctx, next.Timeouts.Update, diags)
	if !ok {
		return
	}
	defer cancel()
	write := &deploymentWriter[apigen.AzureDeployment]{
		cloud:     r.cloud(),
		target:    next.targetLabel(),
		unchanged: r.unchangedSince(&prior, diags),
		ref:       client.DeploymentRef{ID: prior.ID.ValueString(), ETag: privateString(ctx, req.Private, privateETag)},
		diags:     diags,
	}
	if !write.runAll(ctx, r.updateSteps(ctx, &next, &prior, diags)) {
		return
	}
	if result, ok := write.latest(ctx); ok {
		r.store(ctx, azureStored{model: &next, result: result, state: &resp.State, private: resp.Private, diags: diags})
		r.reportStatus(&next, diags)
	}
}

func (r *azureDeploymentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.writeAccess().refuseAtApply(r.data, "destroys", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var model azureDeploymentModel
	if diags.Append(req.State.Get(ctx, &model)...); diags.HasError() {
		return
	}
	ref := client.DeploymentRef{ID: model.ID.ValueString(), ETag: privateString(ctx, req.Private, privateETag)}
	cleanup, err := r.disconnect(ctx, ref)
	if err != nil {
		r.errors().addDeleteError(ref.ID, err, diags)
		return
	}
	reportCleanup(cleanupReport{target: model.targetLabel(), side: azureWording.side, items: cleanup}, diags)
}

func (r *azureDeploymentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := r.resolveImportID(ctx, strings.TrimSpace(req.ID), &resp.Diagnostics)
	if ok {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	}
}

func (r *azureDeploymentResource) disconnect(ctx context.Context, ref client.DeploymentRef) ([]apigen.CleanupItem, error) {
	cleanup, err := r.data.Client.DeleteAzureDeployment(ctx, ref)
	if !client.IsStatus(err, http.StatusPreconditionFailed) {
		return cleanup, err
	}
	fresh, err := r.data.Client.GetAzureDeployment(ctx, ref.ID)
	if err != nil || fresh == nil {
		return nil, err
	}
	ref.ETag = fresh.ETag
	return r.data.Client.DeleteAzureDeployment(ctx, ref)
}

func (r *azureDeploymentResource) errors() deploymentErrors {
	return deploymentErrors{
		title:      azureDeploymentTitle,
		typeName:   r.typeName(),
		wording:    azureWording,
		credential: wireAttribute{wire: "servicePrincipalId", name: "service_principal_id"},
		attributes: azureWireAttributes,
	}
}

func (r *azureDeploymentResource) cloud() deploymentCloud[apigen.AzureDeployment] {
	return deploymentCloud[apigen.AzureDeployment]{
		errors:     r.errors(),
		policy:     &azureVerification,
		get:        r.data.Client.GetAzureDeployment,
		consoleURL: func(item apigen.AzureDeployment) *string { return item.ConsoleURL },
		active:     func(item apigen.AzureDeployment) bool { return item.Status == apigen.DeploymentStatusActive },
	}
}

func (r *azureDeploymentResource) writeAccess() writeAccess {
	return writeAccess{scope: deploymentsWriteScope, typeName: r.typeName()}
}

func withAzureTimeout(ctx context.Context, read func(context.Context, time.Duration) (time.Duration, diag.Diagnostics), diags *diag.Diagnostics) (context.Context, context.CancelFunc, bool) {
	timeout, timeoutDiags := read(ctx, defaultAzureDeploymentTimeout)
	if diags.Append(timeoutDiags...); diags.HasError() {
		return ctx, func() {}, false
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	return bounded, cancel, true
}

func (r *azureDeploymentResource) planDestroy(ctx context.Context, state tfsdk.State, diags *diag.Diagnostics) {
	var prior azureDeploymentModel
	if diags.Append(state.Get(ctx, &prior)...); diags.HasError() {
		return
	}
	if prior.DeletionProtection.ValueBool() {
		r.errors().refuseProtectedDestroy(prior.ID.ValueString(), diags)
	}
}

func (r *azureDeploymentResource) planUpdate(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	diags := &resp.Diagnostics
	var next, prior azureDeploymentModel
	diags.Append(req.Plan.Get(ctx, &next)...)
	if diags.Append(req.State.Get(ctx, &prior)...); diags.HasError() {
		return
	}
	if replacesAzureDeployment(&next, &prior) && prior.DeletionProtection.ValueBool() {
		r.errors().refuseProtectedReplacement(prior.ID.ValueString(), diags)
		return
	}
	if !healsAzure(&next, &prior) {
		return
	}
	for _, attribute := range []string{"status", "consent_url", "error_code", "error_message"} {
		diags.Append(resp.Plan.SetAttribute(ctx, path.Root(attribute), types.StringUnknown())...)
	}
}

func replacesAzureDeployment(next, prior *azureDeploymentModel) bool {
	return changedValue(next.DeploymentID, prior.DeploymentID) ||
		changedValue(next.DeploymentMethod, prior.DeploymentMethod) ||
		changedValue(next.SubscriptionID, prior.SubscriptionID) ||
		changedValue(next.ManagementGroupID, prior.ManagementGroupID) ||
		changedValue(next.AzureTenantID, prior.AzureTenantID)
}

func healsAzure(next, prior *azureDeploymentModel) bool {
	return prior.Status.ValueString() == string(apigen.DeploymentStatusFailed) && next.ReverifyOnFailure.ValueBool()
}

func (r *azureDeploymentResource) createVerified(ctx context.Context, body apigen.AzureDeploymentCreate) (*client.AzureDeploymentResult, verificationOutcome, error) {
	var result *client.AzureDeploymentResult
	outcome, err := azureVerification.run(ctx, func(ctx context.Context) error {
		var callErr error
		result, callErr = r.data.Client.CreateAzureDeployment(ctx, client.DeploymentCreateRequest[apigen.AzureDeploymentCreate]{Body: body, IdempotencyKey: idempotencyKey()})
		return callErr
	})
	return result, outcome, err
}

func (r *azureDeploymentResource) updateSteps(ctx context.Context, next, prior *azureDeploymentModel, diags *diag.Diagnostics) []deploymentStep[apigen.AzureDeployment] {
	patch := next.patchFrom(ctx, prior, diags)
	return []deploymentStep[apigen.AzureDeployment]{
		{
			action: "update",
			needed: func(*client.AzureDeploymentResult) bool { return len(patch) > 0 },
			send: func(ctx context.Context, ref client.DeploymentRef) (*client.AzureDeploymentResult, error) {
				return r.data.Client.UpdateAzureDeployment(ctx, client.DeploymentUpdateRequest{DeploymentRef: ref, Patch: patch})
			},
		},
		{
			action: "verify",
			needed: func(last *client.AzureDeploymentResult) bool {
				return healsAzure(next, prior) && (last == nil || last.Deployment.Status == apigen.DeploymentStatusFailed)
			},
			send:     r.data.Client.VerifyAzureDeployment,
			announce: true,
		},
	}
}

func (r *azureDeploymentResource) unchangedSince(prior *azureDeploymentModel, diags *diag.Diagnostics) func(ctx context.Context, fresh apigen.AzureDeployment) bool {
	return func(ctx context.Context, fresh apigen.AzureDeployment) bool {
		remote := *prior
		remote.writeFrom(ctx, fresh, diags)
		return remote.sameIntent(prior)
	}
}

type azureStored struct {
	model   *azureDeploymentModel
	result  *client.AzureDeploymentResult
	state   *tfsdk.State
	private privateSetter
	diags   *diag.Diagnostics
	quiet   bool
}

func (r *azureDeploymentResource) store(ctx context.Context, s azureStored) {
	s.model.writeFrom(ctx, s.result.Deployment, s.diags)
	s.diags.Append(s.state.Set(ctx, s.model)...)
	setPrivate(ctx, s.private, privateETag, s.result.ETag, s.diags)
	if !s.quiet {
		addDeploymentWarnings(s.diags, s.result.Deployment.Warnings)
	}
}

func (r *azureDeploymentResource) reportStatus(model *azureDeploymentModel, diags *diag.Diagnostics) {
	switch apigen.DeploymentStatus(model.Status.ValueString()) {
	case apigen.DeploymentStatusPendingConsent:
		r.warnPendingConsent(model, diags)
	case apigen.DeploymentStatusFailed:
		r.warnFailing(model, diags)
	case apigen.DeploymentStatusActive:
	}
}

func (r *azureDeploymentResource) warnPendingConsent(model *azureDeploymentModel, diags *diag.Diagnostics) {
	approver := "an Application Administrator or a Cloud Application Administrator"
	if model.IncludeEntraID.ValueBool() {
		approver = "a Global Administrator or a Privileged Role Administrator, because include_entra_id is true"
	}
	diags.AddWarning(
		"An Entra admin must approve Act",
		fmt.Sprintf("Act stored %s as pending_consent. Ask %s of directory %s to open this link once and approve Act:\n\n%s\n\nAct verifies the deployment on its own after the approval, and the next refresh shows status active. Nothing in Terraform needs to change.", model.targetLabel(), approver, model.AzureTenantID.ValueString(), model.ConsentURL.ValueString()),
	)
}

func (r *azureDeploymentResource) warnFailing(model *azureDeploymentModel, diags *diag.Diagnostics) {
	next := "The next apply asks Act to verify it again."
	if !model.ReverifyOnFailure.ValueBool() {
		next = "reverify_on_failure is false, so Terraform does not verify it again."
	}
	diags.AddWarning(
		"The "+azureDeploymentTitle+" deployment is failing",
		fmt.Sprintf("Act cannot use the service principal of %s: %s %s. Fix its role assignments, for example by applying the configuration that creates them. %s", model.targetLabel(), model.ErrorCode.ValueString(), model.ErrorMessage.ValueString(), next),
	)
}

func (r *azureDeploymentResource) resolveImportID(ctx context.Context, id string, diags *diag.Diagnostics) (string, bool) {
	if uuidPattern.MatchString(id) {
		return id, true
	}
	lookup, ok := azureImportLookup(id)
	if !ok {
		diags.AddError("Invalid import ID", "Use the deployment ID (a lowercase UUID), subscription/<subscription-id> or management-group/<management-group-id>.")
		return "", false
	}
	return resolveImportByTarget(ctx, r.data.Client, lookup, diags)
}

func azureImportLookup(id string) (importLookup, bool) {
	kind, target, _ := strings.Cut(id, "/")
	switch {
	case kind == azureSubscriptionImport && uuidPattern.MatchString(target):
		return importLookup{cloud: apigen.CloudAzure, scope: apigen.DeploymentScopeSubscription, target: target, label: "Azure subscription"}, true
	case kind == azureManagementGroupImport && azureManagementGroupPattern.MatchString(target):
		return importLookup{cloud: apigen.CloudAzure, scope: apigen.DeploymentScopeManagementGroup, target: target, label: "Azure management group"}, true
	default:
		return importLookup{}, false
	}
}

func (m *azureDeploymentModel) targetLabel() string {
	if !m.ManagementGroupID.IsNull() {
		return "Azure management group " + m.ManagementGroupID.ValueString()
	}
	return "Azure subscription " + m.SubscriptionID.ValueString()
}

func (m *azureDeploymentModel) createBody(ctx context.Context, diags *diag.Diagnostics) apigen.AzureDeploymentCreate {
	body := apigen.AzureDeploymentCreate{
		DeploymentID:       m.DeploymentID.ValueString(),
		AzureTenantID:      m.AzureTenantID.ValueString(),
		SubscriptionID:     knownString(m.SubscriptionID),
		ManagementGroupID:  knownString(m.ManagementGroupID),
		ServicePrincipalID: m.ServicePrincipalID.ValueString(),
		IncludeEntraID:     knownBool(m.IncludeEntraID),
		Name:               knownString(m.Name),
		Tags:               stringMap(ctx, m.Tags, diags),
		DeletionProtection: knownBool(m.DeletionProtection),
	}
	if method := knownString(m.DeploymentMethod); method != nil {
		value := apigen.AzureDeploymentMethod(*method)
		body.DeploymentMethod = &value
	}
	return body
}

func (m *azureDeploymentModel) patchFrom(ctx context.Context, prior *azureDeploymentModel, diags *diag.Diagnostics) client.DeploymentPatch {
	patch := client.DeploymentPatch{}
	if !m.ServicePrincipalID.Equal(prior.ServicePrincipalID) {
		patch["servicePrincipalId"] = m.ServicePrincipalID.ValueString()
	}
	if !m.IncludeEntraID.IsUnknown() && !m.IncludeEntraID.Equal(prior.IncludeEntraID) {
		patch["includeEntraId"] = m.IncludeEntraID.ValueBool()
	}
	if !m.Name.IsUnknown() && !m.Name.Equal(prior.Name) {
		patch["name"] = m.Name.ValueString()
	}
	if !m.Tags.Equal(prior.Tags) {
		tags := map[string]string{}
		if values := stringMap(ctx, m.Tags, diags); values != nil {
			tags = *values
		}
		patch["tags"] = tags
	}
	if !m.DeletionProtection.IsUnknown() && !m.DeletionProtection.Equal(prior.DeletionProtection) {
		patch["deletionProtection"] = m.DeletionProtection.ValueBool()
	}
	return patch
}

func (m *azureDeploymentModel) writeFrom(ctx context.Context, item apigen.AzureDeployment, diags *diag.Diagnostics) {
	m.ID = types.StringValue(item.ID)
	m.DeploymentID = types.StringValue(item.ID)
	m.SubscriptionID = types.StringPointerValue(item.SubscriptionID)
	m.ManagementGroupID = types.StringPointerValue(item.ManagementGroupID)
	m.AzureTenantID = types.StringValue(item.AzureTenantID)
	m.ServicePrincipalID = types.StringPointerValue(item.ServicePrincipalID)
	m.IncludeEntraID = types.BoolValue(item.IncludeEntraID)
	m.Name = types.StringValue(item.Name)
	m.Tags = nullableStringMap(ctx, mapWithPrior{values: item.Tags, prior: m.Tags}, diags)
	m.DeploymentMethod = types.StringNull()
	if item.DeploymentMethod != nil {
		m.DeploymentMethod = types.StringValue(string(*item.DeploymentMethod))
	}
	m.DeletionProtection = types.BoolValue(item.DeletionProtection)
	m.Status = types.StringValue(string(item.Status))
	m.ConsentURL = types.StringPointerValue(item.ConsentURL)
	m.ErrorCode = types.StringPointerValue(item.ErrorCode)
	m.ErrorMessage = types.StringPointerValue(item.ErrorMessage)
	m.UpdateAvailable = types.BoolValue(item.UpdateAvailable)
	m.DeployedVersion = types.StringPointerValue(item.DeployedVersion)
	m.CreatedAt = types.StringValue(item.CreatedAt.UTC().Format(time.RFC3339))
	m.ConsoleURL = types.StringPointerValue(item.ConsoleURL)
	m.CreatedVia = types.StringNull()
	if item.CreatedVia != nil {
		m.CreatedVia = types.StringValue(string(*item.CreatedVia))
	}
}

func (m *azureDeploymentModel) sameIntent(other *azureDeploymentModel) bool {
	return m.SubscriptionID.Equal(other.SubscriptionID) &&
		m.ManagementGroupID.Equal(other.ManagementGroupID) &&
		m.AzureTenantID.Equal(other.AzureTenantID) &&
		m.ServicePrincipalID.Equal(other.ServicePrincipalID) &&
		m.IncludeEntraID.Equal(other.IncludeEntraID) &&
		m.Name.Equal(other.Name) &&
		m.Tags.Equal(other.Tags) &&
		m.DeploymentMethod.Equal(other.DeploymentMethod) &&
		m.DeletionProtection.Equal(other.DeletionProtection)
}

func knownBool(value types.Bool) *bool {
	if value.IsNull() || value.IsUnknown() {
		return nil
	}
	v := value.ValueBool()
	return &v
}

type protectManagementGroupsByDefault struct{}

func (protectManagementGroupsByDefault) Description(context.Context) string {
	return "defaults to true for a management group and false for a subscription"
}

func (m protectManagementGroupsByDefault) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (protectManagementGroupsByDefault) PlanModifyBool(ctx context.Context, req planmodifier.BoolRequest, resp *planmodifier.BoolResponse) {
	if !req.ConfigValue.IsNull() {
		return
	}
	var group types.String
	resp.Diagnostics.Append(req.Plan.GetAttribute(ctx, path.Root("management_group_id"), &group)...)
	if group.IsUnknown() {
		resp.PlanValue = types.BoolUnknown()
		return
	}
	resp.PlanValue = types.BoolValue(!group.IsNull())
}

var azureWireAttributes = map[string]string{
	"deploymentId":       "deployment_id",
	"azureTenantId":      "azure_tenant_id",
	"subscriptionId":     "subscription_id",
	"managementGroupId":  "management_group_id",
	"servicePrincipalId": "service_principal_id",
	"includeEntraId":     "include_entra_id",
	"deploymentMethod":   "deployment_method",
	"name":               "name",
	"tags":               "tags",
	"deletionProtection": "deletion_protection",
}
