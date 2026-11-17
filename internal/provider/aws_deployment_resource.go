package provider

import (
	"context"
	"fmt"
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
	patchTarget(ctx context.Context, prior awsDeploymentModel, patch client.DeploymentPatch, diags *diag.Diagnostics)
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
			MarkdownDescription: "Act capabilities the role was deployed without, so Act does not expect their permissions: `eks_cluster_access` (Kubernetes inside EKS clusters), `cloudtrail_logs` (CloudTrail log files and log events) and `ai_services` (Bedrock, Bedrock AgentCore, OpenSearch Serverless and SageMaker details). Leave it out when the role has every permission group.",
			ElementType:         types.StringType,
			Optional:            true,
			Computed:            true,
			Validators: []validator.Set{setvalidator.ValueStringsAre(stringvalidator.OneOf(
				string(apigen.AwsCapabilityEksClusterAccess),
				string(apigen.AwsCapabilityCloudtrailLogs),
				string(apigen.AwsCapabilityAiServices),
			))},
			PlanModifiers: []planmodifier.Set{setplanmodifier.UseStateForUnknown()},
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

func (r *awsDeploymentResource[M, P]) errors() deploymentErrors {
	return deploymentErrors{
		title:      r.kind.title,
		typeName:   r.typeName(),
		wording:    awsWording,
		credential: wireAttribute{wire: "roleArn", name: "role_arn"},
		attributes: awsWireAttributes,
	}
}

func (r *awsDeploymentResource[M, P]) cloud() deploymentCloud[apigen.AwsDeployment] {
	return deploymentCloud[apigen.AwsDeployment]{
		errors:     r.errors(),
		policy:     &awsVerification,
		get:        r.data.Client.GetAwsDeployment,
		consoleURL: func(item apigen.AwsDeployment) *string { return item.ConsoleURL },
		active:     func(item apigen.AwsDeployment) bool { return item.Status == apigen.DeploymentStatusActive },
	}
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
		r.errors().addWriteError(diags, writeFailure{action: createAction, target: model.targetLabel(), outcome: outcome, err: err})
		return
	}
	r.store(ctx, storedResult[P]{model: model, result: result, state: &resp.State, private: resp.Private, diags: diags})
	diags.AddWarning("Act verified the role", proofOfLife(connectionReport{target: model.targetLabel(), consoleURL: result.Deployment.ConsoleURL, outcome: outcome, wording: awsWording})+r.coverageNote(ctx, result.Deployment.ID))
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
	next, prior := P(&plan), P(&state)
	write := &deploymentWriter[apigen.AwsDeployment]{
		cloud:     r.cloud(),
		target:    next.targetLabel(),
		unchanged: r.unchangedSince(prior, diags),
		ref:       client.DeploymentRef{ID: prior.common().ID.ValueString(), ETag: privateString(ctx, req.Private, privateETag)},
		diags:     diags,
	}
	if !write.runAll(ctx, r.updateSteps(ctx, next, prior, diags)) {
		return
	}
	if result, ok := write.latest(ctx); ok {
		r.store(ctx, storedResult[P]{model: next, result: result, state: &resp.State, private: resp.Private, diags: diags})
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
		r.errors().addDeleteError(model.common().ID.ValueString(), err, diags)
		return
	}
	reportCleanup(cleanupReport{target: model.targetLabel(), side: awsWording.side, items: cleanup}, diags)
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
		r.errors().refuseProtectedDestroy(prior.ID.ValueString(), diags)
	}
}

func (r *awsDeploymentResource[M, P]) planUpdate(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	diags := &resp.Diagnostics
	var plan, state M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	if diags.Append(req.State.Get(ctx, &state)...); diags.HasError() {
		return
	}
	change := planChange{errors: r.errors(), next: P(&plan), prior: P(&state), config: req.Config, plan: &resp.Plan, diags: diags}
	if change.refuseProtectedReplacement() || change.refuseLegacyExternalID() {
		return
	}
	change.planExternalIDRotation(ctx)
	change.planHeal(ctx)
}

type planChange struct {
	errors deploymentErrors
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
	c.errors.refuseProtectedReplacement(prior.ID.ValueString(), c.diags)
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
		result, callErr = r.data.Client.CreateAwsDeployment(ctx, client.DeploymentCreateRequest[apigen.AwsDeploymentCreate]{Body: body, IdempotencyKey: idempotencyKey()})
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
		addDeploymentWarnings(s.diags, s.result.Deployment.Warnings)
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

func (r *awsDeploymentResource[M, P]) updateSteps(ctx context.Context, next, prior P, diags *diag.Diagnostics) []deploymentStep[apigen.AwsDeployment] {
	patch := r.buildPatch(ctx, next, prior, diags)
	change := rotation{prior: prior.common(), next: next.common()}
	return []deploymentStep[apigen.AwsDeployment]{
		{
			action: "update",
			needed: func(*client.AwsDeploymentResult) bool { return len(patch) > 0 },
			send: func(ctx context.Context, ref client.DeploymentRef) (*client.AwsDeploymentResult, error) {
				return r.data.Client.UpdateAwsDeployment(ctx, client.DeploymentUpdateRequest{DeploymentRef: ref, Patch: patch})
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

func (r *awsDeploymentResource[M, P]) unchangedSince(prior P, diags *diag.Diagnostics) func(ctx context.Context, fresh apigen.AwsDeployment) bool {
	return func(ctx context.Context, fresh apigen.AwsDeployment) bool {
		remote := *prior
		copied := P(&remote)
		r.writeState(ctx, copied, fresh, diags)
		return sameIntent(copied.common(), prior.common()) && copied.sameTarget(prior)
	}
}

func (r *awsDeploymentResource[M, P]) resolveImportID(ctx context.Context, id string, diags *diag.Diagnostics) (string, bool) {
	if uuidPattern.MatchString(id) {
		return id, true
	}
	if !r.kind.importKey(id) {
		diags.AddError("Invalid import ID", "Use "+r.kind.importFormats+".")
		return "", false
	}
	return resolveImportByTarget(ctx, r.data.Client, importLookup{cloud: apigen.CloudAws, scope: r.kind.scope, target: id, label: fmt.Sprintf("AWS %s", r.kind.scope)}, diags)
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

func (r *awsDeploymentResource[M, P]) buildPatch(ctx context.Context, model, prior P, diags *diag.Diagnostics) client.DeploymentPatch {
	next, current := model.common(), prior.common()
	patch := client.DeploymentPatch{}
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

var awsWireAttributes = map[string]string{
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
