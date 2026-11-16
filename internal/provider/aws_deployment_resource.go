package provider

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-timeouts/resource/timeouts"
	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/mapvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	defaultDeploymentTimeout = 5 * time.Minute
	maxDeploymentNameLength  = 64
	maxDeploymentTags        = 50
	maxTagKeyLength          = 64
	maxTagValueLength        = 256
	externalIDDerived        = "derived"
	externalIDLegacy         = "legacy"
)

var (
	awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)
	awsRoleArnPattern   = regexp.MustCompile(`^arn:aws:iam::(\d{12}):role(?:/[A-Za-z0-9+=,.@_-]+)+$`)
	awsRegionPattern    = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-\d$`)
	awsOrgIDPattern     = regexp.MustCompile(`^o-[a-z0-9]{10,32}$`)
	awsRootIDPattern    = regexp.MustCompile(`^r-[0-9a-z]{4,32}$`)
	awsOUIDPattern      = regexp.MustCompile(`^ou-[0-9a-z]{4,32}-[0-9a-z]{8,32}$`)
	awsRoleNamePattern  = regexp.MustCompile(`^[A-Za-z0-9+=,.@_-]{1,64}$`)
	awsRolePathPattern  = regexp.MustCompile(`^/(?:[\x21-\x7E]{0,510}/)?$`)
)

type awsDeploymentCommon struct {
	ID                   types.String   `tfsdk:"id"`
	DeploymentID         types.String   `tfsdk:"deployment_id"`
	RoleArn              types.String   `tfsdk:"role_arn"`
	Name                 types.String   `tfsdk:"name"`
	Tags                 types.Map      `tfsdk:"tags"`
	AllowedRegions       types.Set      `tfsdk:"allowed_regions"`
	DisabledCapabilities types.Set      `tfsdk:"disabled_capabilities"`
	DeploymentMethod     types.String   `tfsdk:"deployment_method"`
	DeletionProtection   types.Bool     `tfsdk:"deletion_protection"`
	ExternalIDKeyVersion types.Int64    `tfsdk:"external_id_key_version"`
	ExternalID           types.String   `tfsdk:"external_id"`
	ExternalIDSource     types.String   `tfsdk:"external_id_source"`
	ReverifyOnFailure    types.Bool     `tfsdk:"reverify_on_failure"`
	Status               types.String   `tfsdk:"status"`
	ErrorCode            types.String   `tfsdk:"error_code"`
	ErrorMessage         types.String   `tfsdk:"error_message"`
	UpdateAvailable      types.Bool     `tfsdk:"update_available"`
	DeployedVersion      types.String   `tfsdk:"deployed_version"`
	CreatedAt            types.String   `tfsdk:"created_at"`
	ConsoleURL           types.String   `tfsdk:"console_url"`
	Timeouts             timeouts.Value `tfsdk:"timeouts"`
}

type awsDeploymentModel interface {
	common() *awsDeploymentCommon
	targetLabel() string
	targetKey() types.String
	setTarget(ctx context.Context, body *apigen.AwsDeploymentCreate, diags *diag.Diagnostics)
	patchTarget(ctx context.Context, prior awsDeploymentModel, patch client.AwsDeploymentPatch, diags *diag.Diagnostics)
	readTarget(ctx context.Context, item apigen.AwsDeployment, diags *diag.Diagnostics)
	sameTarget(other awsDeploymentModel) bool
	validate(diags *diag.Diagnostics)
}

type awsDeploymentKind struct {
	suffix            string
	title             string
	description       string
	protectByDefault  bool
	importFormats     string
	scope             apigen.DeploymentScope
	importKey         func(id string) bool
	targetAttributes  func() map[string]schema.Attribute
	wrongScopeMessage string
}

type awsDeploymentResource[M any, P interface {
	*M
	awsDeploymentModel
}] struct {
	kind awsDeploymentKind
	data *ProviderData
}

func (r *awsDeploymentResource[M, P]) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.kind.suffix
}

func (r *awsDeploymentResource[M, P]) typeName() string {
	return "act_" + r.kind.suffix
}

func (r *awsDeploymentResource[M, P]) Schema(ctx context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attributes := map[string]schema.Attribute{
		"id": schema.StringAttribute{
			MarkdownDescription: "The deployment ID, equal to `deployment_id`.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"deployment_id": schema.StringAttribute{
			MarkdownDescription: "The deployment ID Act issued for this target, from `data.act_aws_onboarding_parameters`. Act rejects any other value. Changing it replaces the deployment.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"role_arn": schema.StringAttribute{
			MarkdownDescription: "The ARN of the IAM role Act assumes. Reference the role resource so Terraform creates the role first. Changing it updates the deployment in place and Act verifies the new role.",
			Required:            true,
			Validators:          []validator.String{stringvalidator.RegexMatches(awsRoleArnPattern, "must be an IAM role ARN")},
		},
		"name": schema.StringAttribute{
			MarkdownDescription: "The name Act shows for the deployment, 1 to 64 characters. Act picks one when you leave it out. Changing it updates the deployment in place.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.LengthBetween(1, maxDeploymentNameLength)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"tags": schema.MapAttribute{
			MarkdownDescription: "Act tags for the deployment, at most 50. They are not AWS tags.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Map{
				mapvalidator.SizeAtMost(maxDeploymentTags),
				mapvalidator.KeysAre(stringvalidator.LengthBetween(1, maxTagKeyLength)),
				mapvalidator.ValueStringsAre(stringvalidator.LengthAtMost(maxTagValueLength)),
			},
		},
		"allowed_regions": schema.SetAttribute{
			MarkdownDescription: "The AWS regions Act scans, such as `us-east-1`. Leave it out to scan every region.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Set{
				setvalidator.SizeAtLeast(1),
				setvalidator.ValueStringsAre(stringvalidator.RegexMatches(awsRegionPattern, "must be an AWS region name")),
			},
		},
		"disabled_capabilities": schema.SetAttribute{
			MarkdownDescription: "Act capabilities to turn off for this deployment. The only one today is `eks_cluster_access`.",
			ElementType:         types.StringType,
			Optional:            true,
			Computed:            true,
			Validators:          []validator.Set{setvalidator.ValueStringsAre(stringvalidator.OneOf(string(apigen.AwsCapabilityEksClusterAccess)))},
			PlanModifiers:       []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
		},
		"deployment_method": schema.StringAttribute{
			MarkdownDescription: "How the role was deployed: `terraform` (default) or `cloudformation`. Act cannot change it in place, so changing it replaces the deployment: on a protected deployment, set `deletion_protection = false` and apply that first, or the plan fails. When you import a deployment set up with CloudFormation, set `cloudformation`.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString(string(apigen.AwsDeploymentMethodTerraform)),
			Validators:          []validator.String{stringvalidator.OneOf(string(apigen.AwsDeploymentMethodTerraform), string(apigen.AwsDeploymentMethodCloudformation))},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
		},
		"deletion_protection": schema.BoolAttribute{
			MarkdownDescription: fmt.Sprintf("When true, Act refuses to delete the deployment and a plan that destroys it fails. Defaults to `%t`.", r.kind.protectByDefault),
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(r.kind.protectByDefault),
		},
		"external_id_key_version": schema.Int64Attribute{
			MarkdownDescription: "The key version of the external ID, from `data.act_aws_onboarding_parameters`. Passing it pins the external ID the role trusts, so a key rotation between plan and apply cannot change it. It only changes when `external_id_source` moves from `legacy` to `derived`. Null for a legacy external ID.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.Int64{int64validator.AtLeast(1)},
			PlanModifiers:       []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
		},
		"external_id": schema.StringAttribute{
			MarkdownDescription: "The external ID the role's trust policy must require. Not a secret.",
			Computed:            true,
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"external_id_source": schema.StringAttribute{
			MarkdownDescription: "`derived` for an external ID Act derives from the deployment, or `legacy` for one stored by an older onboarding. Changing `legacy` to `derived` rotates it: Act checks that the role trusts the derived value first. `derived` cannot go back to `legacy`.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.OneOf(externalIDDerived, externalIDLegacy)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"reverify_on_failure": schema.BoolAttribute{
			MarkdownDescription: "When the deployment is `failed`, plan a verification so the next apply makes it active again once the role is fixed. Defaults to `true`. Only the provider uses it.",
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(true),
		},
		"status": schema.StringAttribute{
			MarkdownDescription: "`active` when Act can use the role, `failed` when it cannot.",
			Computed:            true,
		},
		"error_code":    schema.StringAttribute{MarkdownDescription: "Why the deployment failed. Null while active.", Computed: true},
		"error_message": schema.StringAttribute{MarkdownDescription: "What Act saw when the deployment failed. Null while active.", Computed: true},
		"update_available": schema.BoolAttribute{
			MarkdownDescription: "True when the role is older than the version Act recommends.",
			Computed:            true,
		},
		"deployed_version": schema.StringAttribute{MarkdownDescription: "The role version Act detected.", Computed: true},
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
	}
	for name, attribute := range r.kind.targetAttributes() {
		attributes[name] = attribute
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: r.kind.description,
		Attributes:          attributes,
		Blocks: map[string]schema.Block{
			"timeouts": timeouts.Block(ctx, timeouts.Opts{Create: true, Update: true}),
		},
	}
}

func (r *awsDeploymentResource[M, P]) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *awsDeploymentResource[M, P]) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var config M
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	P(&config).validate(&resp.Diagnostics)
}

func (r *awsDeploymentResource[M, P]) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	switch {
	case req.State.Raw.IsNull() && req.Plan.Raw.IsNull():
		return
	case req.State.Raw.IsNull():
		r.planCreate(ctx, req.Plan, &resp.Diagnostics)
	case req.Plan.Raw.IsNull():
		r.planDestroy(ctx, req.State, &resp.Diagnostics)
	default:
		r.planUpdate(ctx, req, resp)
	}
	r.writeAccess().warnAtPlan(r.data, req, resp)
}

func (r *awsDeploymentResource[M, P]) writeAccess() writeAccess {
	return writeAccess{scope: deploymentsWriteScope, typeName: r.typeName()}
}

func (r *awsDeploymentResource[M, P]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "creates", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var plan M
	if diags.Append(req.Plan.Get(ctx, &plan)...); diags.HasError() {
		return
	}
	model := P(&plan)
	body := buildCreateBody(ctx, model, diags)
	timeout, timeoutDiags := model.common().Timeouts.Create(ctx, defaultDeploymentTimeout)
	if diags.Append(timeoutDiags...); diags.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	result, outcome, err := r.createVerified(ctx, body)
	if err != nil {
		r.addWriteError(diags, writeFailure{action: createAction, target: model.targetLabel(), outcome: outcome, err: err})
		return
	}
	r.store(ctx, storedResult[P]{model: model, result: result, state: &resp.State, private: resp.Private, diags: diags})
	diags.AddWarning("Act verified the role", proofOfLife(connectionReport{target: model.targetLabel(), deployment: result.Deployment, outcome: outcome})+r.coverageNote(ctx, result.Deployment.ID))
}

func (r *awsDeploymentResource[M, P]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	diags := &resp.Diagnostics
	var state M
	if diags.Append(req.State.Get(ctx, &state)...); diags.HasError() {
		return
	}
	model := P(&state)
	result, err := r.data.Client.GetAwsDeployment(ctx, model.common().ID.ValueString())
	switch {
	case err != nil:
		diags.AddError("Reading the "+r.kind.title+" deployment failed", err.Error())
	case result == nil:
		resp.State.RemoveResource(ctx)
	case !r.scopeMatches(result.Deployment):
		diags.AddError("Wrong deployment type", fmt.Sprintf("Deployment %s %s", result.Deployment.ID, r.kind.wrongScopeMessage))
	default:
		defaultReverifyOnFailure(model.common())
		r.store(ctx, storedResult[P]{model: model, result: result, state: &resp.State, private: resp.Private, diags: diags, quiet: true})
		r.warnIfFailing(model, diags)
	}
}

func (r *awsDeploymentResource[M, P]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if r.writeAccess().refuseAtApply(r.data, "changes", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var plan, state M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	if diags.Append(req.State.Get(ctx, &state)...); diags.HasError() {
		return
	}
	timeout, timeoutDiags := P(&plan).common().Timeouts.Update(ctx, defaultDeploymentTimeout)
	if diags.Append(timeoutDiags...); diags.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	write := r.newWrite(writeInput[P]{next: P(&plan), prior: P(&state), etag: privateString(ctx, req.Private, privateETag), diags: diags})
	if !write.runAll(ctx, r.updateSteps(ctx, write)) {
		return
	}
	if result, ok := write.latest(ctx); ok {
		r.store(ctx, storedResult[P]{model: write.next, result: result, state: &resp.State, private: resp.Private, diags: diags})
	}
}

func (r *awsDeploymentResource[M, P]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	if r.writeAccess().refuseAtApply(r.data, "destroys", &resp.Diagnostics) {
		return
	}
	diags := &resp.Diagnostics
	var state M
	if diags.Append(req.State.Get(ctx, &state)...); diags.HasError() {
		return
	}
	model := P(&state)
	cleanup, err := r.data.Client.DeleteAwsDeployment(ctx, model.common().ID.ValueString())
	if err != nil {
		r.addDeleteError(model, err, diags)
		return
	}
	reportCleanup(cleanupReport{target: model.targetLabel(), items: cleanup}, diags)
}

func (r *awsDeploymentResource[M, P]) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id, ok := r.resolveImportID(ctx, strings.TrimSpace(req.ID), &resp.Diagnostics)
	if ok {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
	}
}

func (r *awsDeploymentResource[M, P]) planCreate(ctx context.Context, plan tfsdk.Plan, diags *diag.Diagnostics) {
	var model M
	if diags.Append(plan.Get(ctx, &model)...); diags.HasError() {
		return
	}
	if P(&model).common().ExternalIDSource.ValueString() == externalIDLegacy {
		diags.AddAttributeError(path.Root("external_id_source"), "A new deployment cannot use a legacy external ID", "Act gives every new deployment a derived external ID. Leave external_id_source out, or set it to \"derived\".")
	}
}

func (r *awsDeploymentResource[M, P]) planDestroy(ctx context.Context, state tfsdk.State, diags *diag.Diagnostics) {
	var model M
	if diags.Append(state.Get(ctx, &model)...); diags.HasError() {
		return
	}
	if prior := P(&model).common(); prior.DeletionProtection.ValueBool() {
		diags.AddError(
			"The "+r.kind.title+" deployment has deletion protection",
			fmt.Sprintf("Act refuses to delete %s while deletion_protection is true, so this plan stops here instead of failing halfway through the apply. Set deletion_protection = false and apply first. To stop managing it without disconnecting it, use a removed block with lifecycle { destroy = false } or terraform state rm.", prior.ID.ValueString()),
		)
	}
}

func (r *awsDeploymentResource[M, P]) planUpdate(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	diags := &resp.Diagnostics
	var plan, state M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	if diags.Append(req.State.Get(ctx, &state)...); diags.HasError() {
		return
	}
	change := planChange{title: r.kind.title, next: P(&plan), prior: P(&state), config: req.Config, plan: &resp.Plan, diags: diags}
	if change.refuseProtectedReplacement() || change.refuseLegacyExternalID() {
		return
	}
	change.planExternalIDRotation(ctx)
	change.planHeal(ctx)
}

type planChange struct {
	title  string
	next   awsDeploymentModel
	prior  awsDeploymentModel
	config tfsdk.Config
	plan   *tfsdk.Plan
	diags  *diag.Diagnostics
}

func (c planChange) refuseProtectedReplacement() bool {
	next, prior := c.next.common(), c.prior.common()
	key := c.next.targetKey()
	replaced := changedValue(next.DeploymentID, prior.DeploymentID) ||
		changedValue(next.DeploymentMethod, prior.DeploymentMethod) ||
		(!c.prior.targetKey().IsNull() && changedValue(key, c.prior.targetKey()))
	if !replaced || !prior.DeletionProtection.ValueBool() {
		return false
	}
	c.diags.AddError(
		"The "+c.title+" deployment has deletion protection",
		fmt.Sprintf("This change replaces %s, which deletes it first, and Act refuses to delete it while deletion_protection is true. Set deletion_protection = false and apply first.", prior.ID.ValueString()),
	)
	return true
}

func changedValue(next, prior types.String) bool {
	return !next.IsUnknown() && !next.Equal(prior)
}

func (c planChange) refuseLegacyExternalID() bool {
	if c.prior.common().ExternalIDSource.ValueString() != externalIDDerived || c.next.common().ExternalIDSource.ValueString() != externalIDLegacy {
		return false
	}
	c.diags.AddAttributeError(path.Root("external_id_source"), "The external ID cannot go back to legacy", "This deployment already uses a derived external ID. Set external_id_source to \"derived\" or leave it out.")
	return true
}

func (c planChange) planExternalIDRotation(ctx context.Context) {
	next, prior := c.next.common(), c.prior.common()
	if rotatesExternalID(rotation{prior: prior, next: next}) {
		c.diags.Append(c.plan.SetAttribute(ctx, path.Root("external_id"), types.StringUnknown())...)
		var configured types.Int64
		c.diags.Append(c.config.GetAttribute(ctx, path.Root("external_id_key_version"), &configured)...)
		if configured.IsNull() {
			c.diags.Append(c.plan.SetAttribute(ctx, path.Root("external_id_key_version"), types.Int64Unknown())...)
		}
		return
	}
	if next.ExternalIDKeyVersion.IsUnknown() || prior.ExternalIDKeyVersion.IsNull() || next.ExternalIDKeyVersion.Equal(prior.ExternalIDKeyVersion) {
		return
	}
	c.diags.AddAttributeError(
		path.Root("external_id_key_version"),
		"The external ID key version cannot change in place",
		fmt.Sprintf("The deployment's external ID uses key version %d. It only changes when a legacy external ID rotates to derived. Pass external_id_key_version from data.act_aws_onboarding_parameters, which returns the deployment's own value.", prior.ExternalIDKeyVersion.ValueInt64()),
	)
}

func (c planChange) planHeal(ctx context.Context) {
	if !heals(rotation{prior: c.prior.common(), next: c.next.common()}) {
		return
	}
	for _, attribute := range []string{"status", "error_code", "error_message"} {
		c.diags.Append(c.plan.SetAttribute(ctx, path.Root(attribute), types.StringUnknown())...)
	}
}

type rotation struct {
	prior *awsDeploymentCommon
	next  *awsDeploymentCommon
}

func rotatesExternalID(r rotation) bool {
	return r.prior.ExternalIDSource.ValueString() == externalIDLegacy && r.next.ExternalIDSource.ValueString() == externalIDDerived
}

func heals(r rotation) bool {
	return r.prior.Status.ValueString() == string(apigen.DeploymentStatusFailed) && r.next.ReverifyOnFailure.ValueBool()
}

func buildCreateBody(ctx context.Context, model awsDeploymentModel, diags *diag.Diagnostics) apigen.AwsDeploymentCreate {
	c := model.common()
	body := apigen.AwsDeploymentCreate{
		DeploymentID:       c.DeploymentID.ValueString(),
		RoleArn:            c.RoleArn.ValueString(),
		Name:               knownString(c.Name),
		Tags:               stringMap(ctx, c.Tags, diags),
		AllowedRegions:     stringSlice(ctx, c.AllowedRegions, diags),
		DeletionProtection: c.DeletionProtection.ValueBoolPointer(),
	}
	if capabilities := stringSlice(ctx, c.DisabledCapabilities, diags); capabilities != nil {
		values := capabilityList(*capabilities)
		body.DisabledCapabilities = &values
	}
	if method := knownString(c.DeploymentMethod); method != nil {
		value := apigen.AwsDeploymentMethod(*method)
		body.DeploymentMethod = &value
	}
	if !c.ExternalIDKeyVersion.IsUnknown() && !c.ExternalIDKeyVersion.IsNull() {
		version := int(c.ExternalIDKeyVersion.ValueInt64())
		body.ExternalIDKeyVersion = &version
	}
	model.setTarget(ctx, &body, diags)
	return body
}

func (r *awsDeploymentResource[M, P]) createVerified(ctx context.Context, body apigen.AwsDeploymentCreate) (*client.AwsDeploymentResult, verificationOutcome, error) {
	var result *client.AwsDeploymentResult
	outcome, err := awsVerification.run(ctx, func(ctx context.Context) error {
		var callErr error
		result, callErr = r.data.Client.CreateAwsDeployment(ctx, client.AwsDeploymentCreateRequest{Body: body, IdempotencyKey: idempotencyKey()})
		return callErr
	})
	return result, outcome, err
}

func (r *awsDeploymentResource[M, P]) coverageNote(ctx context.Context, id string) string {
	if r.kind.scope != apigen.DeploymentScopeOrganization {
		return ""
	}
	coverage, err := r.data.Client.GetDeploymentCoverage(ctx, id)
	if err != nil {
		return "\n\nAct could not report the coverage yet (" + err.Error() + "). Read data.act_deployment_coverage to follow it."
	}
	return fmt.Sprintf(
		"\n\nCoverage now: %d of %d accounts connected, %d pending, %d failed. Account discovery is %s. Read data.act_deployment_coverage to follow it; the resource does not store it.",
		coverage.AccountsConnected, coverage.AccountsExpected, coverage.AccountsPending, coverage.AccountsFailed, coverage.DiscoveryState,
	)
}

type storedResult[P awsDeploymentModel] struct {
	model   P
	result  *client.AwsDeploymentResult
	state   *tfsdk.State
	private privateSetter
	diags   *diag.Diagnostics
	quiet   bool
}

func (r *awsDeploymentResource[M, P]) store(ctx context.Context, s storedResult[P]) {
	r.writeState(ctx, s.model, s.result.Deployment, s.diags)
	s.diags.Append(s.state.Set(ctx, s.model)...)
	setPrivate(ctx, s.private, privateETag, s.result.ETag, s.diags)
	if !s.quiet {
		addDeploymentWarnings(s.diags, s.result.Deployment)
	}
}

func defaultReverifyOnFailure(c *awsDeploymentCommon) {
	if c.ReverifyOnFailure.IsNull() {
		c.ReverifyOnFailure = types.BoolValue(true)
	}
}

func (r *awsDeploymentResource[M, P]) warnIfFailing(model P, diags *diag.Diagnostics) {
	c := model.common()
	if c.Status.ValueString() != string(apigen.DeploymentStatusFailed) {
		return
	}
	next := "The next apply asks Act to verify it again."
	if !c.ReverifyOnFailure.ValueBool() {
		next = "reverify_on_failure is false, so Terraform does not verify it again."
	}
	diags.AddWarning(
		"The "+r.kind.title+" deployment is failing",
		fmt.Sprintf("Act cannot use the role of %s: %s %s. Fix the role, for example by applying the configuration that creates it. %s", model.targetLabel(), c.ErrorCode.ValueString(), c.ErrorMessage.ValueString(), next),
	)
}

type writeInput[P awsDeploymentModel] struct {
	next  P
	prior P
	etag  string
	diags *diag.Diagnostics
}

type deploymentWrite[M any, P interface {
	*M
	awsDeploymentModel
}] struct {
	resource *awsDeploymentResource[M, P]
	next     P
	prior    P
	ref      client.AwsDeploymentRef
	result   *client.AwsDeploymentResult
	diags    *diag.Diagnostics
}

type writeStep struct {
	action   string
	needed   func(last *client.AwsDeploymentResult) bool
	send     func(ctx context.Context, ref client.AwsDeploymentRef) (*client.AwsDeploymentResult, error)
	announce bool
}

func (r *awsDeploymentResource[M, P]) newWrite(in writeInput[P]) *deploymentWrite[M, P] {
	return &deploymentWrite[M, P]{
		resource: r,
		next:     in.next,
		prior:    in.prior,
		ref:      client.AwsDeploymentRef{ID: in.prior.common().ID.ValueString(), ETag: in.etag},
		diags:    in.diags,
	}
}

func (r *awsDeploymentResource[M, P]) updateSteps(ctx context.Context, w *deploymentWrite[M, P]) []writeStep {
	patch := r.buildPatch(ctx, w.next, w.prior, w.diags)
	change := rotation{prior: w.prior.common(), next: w.next.common()}
	return []writeStep{
		{
			action: "update",
			needed: func(*client.AwsDeploymentResult) bool { return len(patch) > 0 },
			send: func(ctx context.Context, ref client.AwsDeploymentRef) (*client.AwsDeploymentResult, error) {
				return r.data.Client.UpdateAwsDeployment(ctx, client.AwsDeploymentUpdateRequest{AwsDeploymentRef: ref, Patch: patch})
			},
		},
		{
			action: "rotate the external ID of",
			needed: func(*client.AwsDeploymentResult) bool { return rotatesExternalID(change) },
			send:   r.data.Client.RotateAwsExternalID,
		},
		{
			action: "verify",
			needed: func(last *client.AwsDeploymentResult) bool {
				return heals(change) && (last == nil || last.Deployment.Status != apigen.DeploymentStatusActive)
			},
			send:     r.data.Client.VerifyAwsDeployment,
			announce: true,
		},
	}
}

func (w *deploymentWrite[M, P]) runAll(ctx context.Context, steps []writeStep) bool {
	if w.diags.HasError() {
		return false
	}
	for _, step := range steps {
		if step.needed(w.result) && !w.run(ctx, step) {
			return false
		}
	}
	return true
}

func (w *deploymentWrite[M, P]) run(ctx context.Context, step writeStep) bool {
	outcome, err := awsVerification.run(ctx, func(ctx context.Context) error { return w.sendOnce(ctx, step) })
	if err != nil {
		if !w.diags.HasError() {
			w.resource.addWriteError(w.diags, writeFailure{action: step.action, target: w.next.targetLabel(), outcome: outcome, err: err})
		}
		return false
	}
	w.ref.ETag = w.result.ETag
	if step.announce {
		w.diags.AddWarning("Act verified the role again", proofOfLife(connectionReport{target: w.next.targetLabel(), deployment: w.result.Deployment, outcome: outcome, reconnected: true}))
	}
	return true
}

func (w *deploymentWrite[M, P]) sendOnce(ctx context.Context, step writeStep) error {
	result, err := step.send(ctx, w.ref)
	if client.IsStatus(err, http.StatusPreconditionFailed) && w.refreshETag(ctx) {
		result, err = step.send(ctx, w.ref)
	}
	if err == nil {
		w.result = result
	}
	return err
}

func (w *deploymentWrite[M, P]) refreshETag(ctx context.Context) bool {
	fresh, err := w.resource.data.Client.GetAwsDeployment(ctx, w.ref.ID)
	switch {
	case err != nil:
		w.diags.AddError("Reading the "+w.resource.kind.title+" deployment failed", fmt.Sprintf("Act answered 412 for deployment %s, and reading it again failed: %v", w.ref.ID, err))
		return false
	case fresh == nil:
		w.diags.AddError("The "+w.resource.kind.title+" deployment is gone", fmt.Sprintf("Deployment %s was deleted in Act during this apply. Run terraform apply again to create it.", w.ref.ID))
		return false
	}
	remote := *w.prior
	copied := P(&remote)
	w.resource.writeState(ctx, copied, fresh.Deployment, w.diags)
	if !sameIntent(copied.common(), w.prior.common()) || !copied.sameTarget(w.prior) {
		w.diags.AddError(
			"The "+w.resource.kind.title+" deployment changed in Act",
			fmt.Sprintf("Someone changed deployment %s since Terraform last read it, so nothing was sent. Run terraform apply again to plan against the current settings.", w.ref.ID),
		)
		return false
	}
	w.ref.ETag = fresh.ETag
	return true
}

func (w *deploymentWrite[M, P]) latest(ctx context.Context) (*client.AwsDeploymentResult, bool) {
	if w.result != nil {
		return w.result, true
	}
	fresh, err := w.resource.data.Client.GetAwsDeployment(ctx, w.ref.ID)
	switch {
	case err != nil:
		w.diags.AddError("Reading the "+w.resource.kind.title+" deployment failed", err.Error())
		return nil, false
	case fresh == nil:
		w.diags.AddError("The "+w.resource.kind.title+" deployment is gone", fmt.Sprintf("Deployment %s was deleted in Act during this apply. Run terraform apply again to create it.", w.ref.ID))
		return nil, false
	}
	return fresh, true
}

func (r *awsDeploymentResource[M, P]) addDeleteError(model P, err error, diags *diag.Diagnostics) {
	id := model.common().ID.ValueString()
	var apiErr *client.APIError
	if asAPIError(err, &apiErr) && apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeDeletionProtected) {
		diags.AddError("The "+r.kind.title+" deployment has deletion protection", fmt.Sprintf("Act refused to delete %s. Set deletion_protection = false and apply before you destroy it.", id))
		return
	}
	diags.AddError("Disconnecting the "+r.kind.title+" deployment failed", err.Error())
}

type cleanupReport struct {
	target string
	items  []apigen.CleanupItem
}

func reportCleanup(report cleanupReport, diags *diag.Diagnostics) {
	if len(report.items) == 0 {
		return
	}
	lines := make([]string, 0, len(report.items))
	for _, item := range report.items {
		lines = append(lines, "- "+item.Resource+": "+item.Description)
	}
	diags.AddWarning("Act disconnected "+report.target, "Act stopped scanning and deleted the credentials it held. These still exist in AWS:\n\n"+strings.Join(lines, "\n"))
}

func (r *awsDeploymentResource[M, P]) resolveImportID(ctx context.Context, id string, diags *diag.Diagnostics) (string, bool) {
	if uuidPattern.MatchString(id) {
		return id, true
	}
	if !r.kind.importKey(id) {
		diags.AddError("Invalid import ID", "Use "+r.kind.importFormats+".")
		return "", false
	}
	matches, err := r.deploymentsCovering(ctx, id)
	if err != nil {
		diags.AddError("Listing deployments failed", err.Error())
		return "", false
	}
	switch len(matches) {
	case 0:
		diags.AddError("No deployment to import", fmt.Sprintf("This tenant has no AWS %s deployment for %s.", r.kind.scope, id))
		return "", false
	case 1:
		return matches[0], true
	default:
		diags.AddError("More than one deployment matches", fmt.Sprintf("Deployments %s all cover %s. Import one by its ID.", strings.Join(matches, ", "), id))
		return "", false
	}
}

func (r *awsDeploymentResource[M, P]) deploymentsCovering(ctx context.Context, target string) ([]string, error) {
	cloud := apigen.CloudAws
	items, err := r.data.Client.ListDeployments(ctx, client.DeploymentFilter{Cloud: &cloud, Target: &target})
	if err != nil {
		return nil, err
	}
	matches := []string{}
	for _, item := range items {
		if item.Scope == r.kind.scope {
			matches = append(matches, item.ID)
		}
	}
	return matches, nil
}

func (r *awsDeploymentResource[M, P]) scopeMatches(item apigen.AwsDeployment) bool {
	if r.kind.scope == apigen.DeploymentScopeOrganization {
		return item.Organization != nil
	}
	return item.Organization == nil
}

func (r *awsDeploymentResource[M, P]) writeState(ctx context.Context, model P, item apigen.AwsDeployment, diags *diag.Diagnostics) {
	c := model.common()
	c.ID = types.StringValue(item.ID)
	c.DeploymentID = types.StringValue(item.ID)
	c.RoleArn = types.StringPointerValue(item.RoleArn)
	c.Name = types.StringValue(item.Name)
	c.Tags = nullableStringMap(ctx, mapWithPrior{values: item.Tags, prior: c.Tags}, diags)
	c.AllowedRegions = nullableStringSet(ctx, item.AllowedRegions, diags)
	c.DisabledCapabilities = stringSet(ctx, capabilityNames(item.DisabledCapabilities), diags)
	c.DeploymentMethod = types.StringNull()
	if item.DeploymentMethod != nil {
		c.DeploymentMethod = types.StringValue(string(*item.DeploymentMethod))
	}
	c.DeletionProtection = types.BoolValue(item.DeletionProtection)
	c.ExternalIDKeyVersion = int64Pointer(item.ExternalIDKeyVersion)
	c.ExternalID = types.StringValue(item.ExternalID)
	c.ExternalIDSource = types.StringValue(string(item.ExternalIDSource))
	c.Status = types.StringValue(string(item.Status))
	c.ErrorCode = types.StringPointerValue(item.ErrorCode)
	c.ErrorMessage = types.StringPointerValue(item.ErrorMessage)
	c.UpdateAvailable = types.BoolValue(item.UpdateAvailable)
	c.DeployedVersion = types.StringPointerValue(item.DeployedVersion)
	c.CreatedAt = types.StringValue(item.CreatedAt.UTC().Format(time.RFC3339))
	c.ConsoleURL = types.StringPointerValue(item.ConsoleURL)
	model.readTarget(ctx, item, diags)
}

func (r *awsDeploymentResource[M, P]) buildPatch(ctx context.Context, model, prior P, diags *diag.Diagnostics) client.AwsDeploymentPatch {
	next, current := model.common(), prior.common()
	patch := client.AwsDeploymentPatch{}
	if !next.RoleArn.Equal(current.RoleArn) {
		patch["roleArn"] = next.RoleArn.ValueString()
	}
	if !next.Name.IsUnknown() && !next.Name.Equal(current.Name) {
		patch["name"] = next.Name.ValueString()
	}
	if !next.Tags.Equal(current.Tags) {
		tags := map[string]string{}
		if values := stringMap(ctx, next.Tags, diags); values != nil {
			tags = *values
		}
		patch["tags"] = tags
	}
	if !next.AllowedRegions.Equal(current.AllowedRegions) {
		patch["allowedRegions"] = sliceOrNil(stringSlice(ctx, next.AllowedRegions, diags))
	}
	if !next.DisabledCapabilities.IsUnknown() && !next.DisabledCapabilities.Equal(current.DisabledCapabilities) {
		values := []string{}
		if list := stringSlice(ctx, next.DisabledCapabilities, diags); list != nil {
			values = *list
		}
		patch["disabledCapabilities"] = values
	}
	if !next.DeletionProtection.IsUnknown() && !next.DeletionProtection.Equal(current.DeletionProtection) {
		patch["deletionProtection"] = next.DeletionProtection.ValueBool()
	}
	model.patchTarget(ctx, prior, patch, diags)
	return patch
}

const createAction = "create"

type writeFailure struct {
	action  string
	target  string
	outcome verificationOutcome
	err     error
}

type alreadyExistsDetails struct {
	DeploymentID string `json:"deploymentId"`
}

type invalidRequestDetails struct {
	Attribute string `json:"attribute"`
	Reason    string `json:"reason"`
}

func (r *awsDeploymentResource[M, P]) addWriteError(diags *diag.Diagnostics, failure writeFailure) {
	summary := fmt.Sprintf("Could not %s the %s deployment", failure.action, r.kind.title)
	var apiErr *client.APIError
	if !asAPIError(failure.err, &apiErr) {
		diags.AddError(summary, failure.err.Error())
		return
	}
	switch apigen.ErrorEnvelopeErrorCode(apiErr.Code) {
	case apigen.ErrorEnvelopeErrorCodeAlreadyExists:
		diags.AddError(summary, r.importInstead(apiErr, failure.target))
	case apigen.ErrorEnvelopeErrorCodeVerificationFailed:
		addVerificationError(diags, summary, failure)
	case apigen.ErrorEnvelopeErrorCodePreconditionFailed:
		diags.AddError(summary, "The deployment changed in Act since Terraform last read it. Run terraform apply again to plan against the current settings.")
	case apigen.ErrorEnvelopeErrorCodeInvalidRequest:
		addInvalidRequestError(diags, summary, apiErr)
	default:
		diags.AddError(summary, apiErr.Error())
	}
}

func (r *awsDeploymentResource[M, P]) importInstead(apiErr *client.APIError, target string) string {
	var details alreadyExistsDetails
	existing := target
	if apiErr.DecodeDetails(&details) == nil && details.DeploymentID != "" {
		existing = details.DeploymentID
	}
	return fmt.Sprintf("Act already has a deployment for %s. Terraform does not take it over silently. Import it instead:\n\nimport {\n  to = %s.<name>\n  id = %q\n}", target, r.typeName(), existing)
}

func addVerificationError(diags *diag.Diagnostics, summary string, failure writeFailure) {
	verification, _ := asVerificationFailure(failure.err)
	detail := verification.describe(failure)
	if verification.Attribute == "roleArn" || verification.Attribute == "" {
		diags.AddAttributeError(path.Root("role_arn"), summary, detail)
		return
	}
	diags.AddError(summary, detail)
}

func addInvalidRequestError(diags *diag.Diagnostics, summary string, apiErr *client.APIError) {
	var details invalidRequestDetails
	if apiErr.DecodeDetails(&details) != nil || wireAttributes[details.Attribute] == "" {
		diags.AddError(summary, apiErr.Error())
		return
	}
	attribute := wireAttributes[details.Attribute]
	diags.AddAttributeError(path.Root(attribute), summary, fmt.Sprintf("Act rejected %s: %s.", attribute, details.Reason))
}

func (f *verificationFailure) describe(failure writeFailure) string {
	return f.whatActSaw() + f.whyItStopped(failure.outcome) + whatWasKept(failure.action)
}

func (f *verificationFailure) whatActSaw() string {
	detail := "Act could not use the role: " + f.CloudErrorCode + "."
	if f.Hint == "" {
		return detail
	}
	return detail + " " + asSentence(f.Hint)
}

func (f *verificationFailure) whyItStopped(outcome verificationOutcome) string {
	switch {
	case f.RetryClass == retryClassPropagation && outcome.timedOut:
		return fmt.Sprintf(" Act kept trying for %s (%d attempts) while AWS propagated the role, then gave up. Apply again, or raise timeouts if the role takes longer to propagate.", outcome.elapsed.Round(time.Second), outcome.attempts)
	case outcome.attempts > 1:
		return fmt.Sprintf(" Act got the same answer %d times, so this needs a fix on the AWS side.", outcome.attempts)
	default:
		return ""
	}
}

func whatWasKept(action string) string {
	if action != createAction {
		return ""
	}
	return " Nothing was stored."
}

func asSentence(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" || strings.ContainsAny(trimmed[len(trimmed)-1:], ".!?") {
		return trimmed
	}
	return trimmed + "."
}

type connectionReport struct {
	target      string
	deployment  apigen.AwsDeployment
	outcome     verificationOutcome
	reconnected bool
}

func proofOfLife(report connectionReport) string {
	message := "Connected. Act started the first scan of " + report.target + "."
	if report.reconnected {
		message = "Connected again. Act can use the role of " + report.target + "."
	}
	if report.deployment.ConsoleURL != nil {
		message += " Open " + *report.deployment.ConsoleURL
	}
	if report.outcome.attempts > 1 {
		message += fmt.Sprintf("\n\nVerified after %s and %d attempts while AWS propagated the role.", report.outcome.elapsed.Round(time.Second), report.outcome.attempts)
	}
	return message
}

func addDeploymentWarnings(diags *diag.Diagnostics, item apigen.AwsDeployment) {
	for _, warning := range item.Warnings {
		diags.AddWarning("Act: "+warning.Code, warning.Message)
	}
}

var wireAttributes = map[string]string{
	"deploymentId":                       "deployment_id",
	"roleArn":                            "role_arn",
	"name":                               "name",
	"tags":                               "tags",
	"allowedRegions":                     "allowed_regions",
	"disabledCapabilities":               "disabled_capabilities",
	"deploymentMethod":                   "deployment_method",
	"externalIdKeyVersion":               "external_id_key_version",
	"accountId":                          "account_id",
	"organization.organizationId":        "organization_id",
	"organization.rootId":                "root_id",
	"organization.organizationalUnitIds": "organizational_unit_ids",
	"organization.excludedAccountIds":    "excluded_account_ids",
	"organization.memberRoleName":        "member_role_name",
	"organization.memberRolePath":        "member_role_path",
}

func sameIntent(a, b *awsDeploymentCommon) bool {
	return a.RoleArn.Equal(b.RoleArn) &&
		a.Name.Equal(b.Name) &&
		a.Tags.Equal(b.Tags) &&
		a.AllowedRegions.Equal(b.AllowedRegions) &&
		a.DisabledCapabilities.Equal(b.DisabledCapabilities) &&
		a.DeploymentMethod.Equal(b.DeploymentMethod) &&
		a.DeletionProtection.Equal(b.DeletionProtection) &&
		a.ExternalIDSource.Equal(b.ExternalIDSource)
}
