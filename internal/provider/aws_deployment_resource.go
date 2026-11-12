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
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const (
	defaultDeploymentTimeout = 5 * time.Minute
	externalIDDerived        = "derived"
	externalIDLegacy         = "legacy"
)

var (
	awsAccountIDPattern = regexp.MustCompile(`^\d{12}$`)
	awsRoleArnPattern   = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:iam::(\d{12}):role(?:/[A-Za-z0-9+=,.@_-]+)+$`)
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
			MarkdownDescription: "The name Act shows for the deployment, 1 to 64 characters. Act picks one when you leave it out.",
			Optional:            true,
			Computed:            true,
			Validators:          []validator.String{stringvalidator.LengthBetween(1, 64)},
			PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
		},
		"tags": schema.MapAttribute{
			MarkdownDescription: "Act tags for the deployment, at most 50. They are not AWS tags.",
			ElementType:         types.StringType,
			Optional:            true,
			Validators: []validator.Map{
				mapvalidator.SizeAtMost(50),
				mapvalidator.KeysAre(stringvalidator.LengthBetween(1, 64)),
				mapvalidator.ValueStringsAre(stringvalidator.LengthAtMost(256)),
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
			MarkdownDescription: "How the role was deployed: `terraform` (default) or `cloudformation`.",
			Optional:            true,
			Computed:            true,
			Default:             stringdefault.StaticString(string(apigen.AwsDeploymentMethodTerraform)),
			Validators:          []validator.String{stringvalidator.OneOf(string(apigen.AwsDeploymentMethodTerraform), string(apigen.AwsDeploymentMethodCloudformation))},
		},
		"deletion_protection": schema.BoolAttribute{
			MarkdownDescription: fmt.Sprintf("When true, Act refuses to delete the deployment and a plan that destroys it fails. Defaults to `%t`.", r.kind.protectByDefault),
			Optional:            true,
			Computed:            true,
			Default:             booldefault.StaticBool(r.kind.protectByDefault),
		},
		"external_id_key_version": schema.Int64Attribute{
			MarkdownDescription: "The key version of the external ID, from `data.act_aws_onboarding_parameters`. Passing it pins the external ID the role trusts, so a key rotation between plan and apply cannot change it. It only changes when `external_id_source` moves from `legacy` to `derived`.",
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
			MarkdownDescription: "The deployment's page in the Act console.",
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
	diags := &resp.Diagnostics
	if req.State.Raw.IsNull() {
		if req.Plan.Raw.IsNull() {
			return
		}
		var plan M
		diags.Append(req.Plan.Get(ctx, &plan)...)
		if !diags.HasError() && P(&plan).common().ExternalIDSource.ValueString() == externalIDLegacy {
			diags.AddAttributeError(path.Root("external_id_source"), "A new deployment cannot use a legacy external ID", "Act gives every new deployment a derived external ID. Leave external_id_source out, or set it to \"derived\".")
		}
		return
	}
	var state M
	diags.Append(req.State.Get(ctx, &state)...)
	if diags.HasError() {
		return
	}
	prior := P(&state).common()
	if req.Plan.Raw.IsNull() {
		if prior.DeletionProtection.ValueBool() {
			diags.AddError(
				"The "+r.kind.title+" deployment has deletion protection",
				fmt.Sprintf("Act refuses to delete %s while deletion_protection is true, so this plan stops here instead of failing halfway through the apply. Set deletion_protection = false and apply first. To stop managing it without disconnecting it, use a removed block with lifecycle { destroy = false } or terraform state rm.", prior.ID.ValueString()),
			)
		}
		return
	}
	var plan M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	if diags.HasError() {
		return
	}
	next := P(&plan).common()
	replaced := !next.DeploymentID.IsUnknown() && !next.DeploymentID.Equal(prior.DeploymentID)
	if key := P(&plan).targetKey(); !key.IsUnknown() && !key.Equal(P(&state).targetKey()) {
		replaced = true
	}
	if replaced && prior.DeletionProtection.ValueBool() {
		diags.AddError(
			"The "+r.kind.title+" deployment has deletion protection",
			fmt.Sprintf("This change replaces %s, which deletes it first, and Act refuses to delete it while deletion_protection is true. Set deletion_protection = false and apply first.", prior.ID.ValueString()),
		)
		return
	}
	rotating := prior.ExternalIDSource.ValueString() == externalIDLegacy && next.ExternalIDSource.ValueString() == externalIDDerived
	if prior.ExternalIDSource.ValueString() == externalIDDerived && next.ExternalIDSource.ValueString() == externalIDLegacy {
		diags.AddAttributeError(path.Root("external_id_source"), "The external ID cannot go back to legacy", "This deployment already uses a derived external ID. Set external_id_source to \"derived\" or leave it out.")
		return
	}
	if rotating {
		diags.Append(resp.Plan.SetAttribute(ctx, path.Root("external_id"), types.StringUnknown())...)
		var configured types.Int64
		diags.Append(req.Config.GetAttribute(ctx, path.Root("external_id_key_version"), &configured)...)
		if configured.IsNull() {
			diags.Append(resp.Plan.SetAttribute(ctx, path.Root("external_id_key_version"), types.Int64Unknown())...)
		}
	} else if !next.ExternalIDKeyVersion.IsUnknown() && !prior.ExternalIDKeyVersion.IsNull() && !next.ExternalIDKeyVersion.Equal(prior.ExternalIDKeyVersion) {
		diags.AddAttributeError(
			path.Root("external_id_key_version"),
			"The external ID key version cannot change in place",
			fmt.Sprintf("The deployment's external ID uses key version %d. It only changes when a legacy external ID rotates to derived. Pass external_id_key_version from data.act_aws_onboarding_parameters, which returns the deployment's own value.", prior.ExternalIDKeyVersion.ValueInt64()),
		)
	}
	if prior.Status.ValueString() == string(apigen.DeploymentStatusFailed) && next.ReverifyOnFailure.ValueBool() {
		for _, attribute := range []string{"status", "error_code", "error_message"} {
			diags.Append(resp.Plan.SetAttribute(ctx, path.Root(attribute), types.StringUnknown())...)
		}
	}
}

func (r *awsDeploymentResource[M, P]) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	diags := &resp.Diagnostics
	var plan M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	if diags.HasError() {
		return
	}
	model := P(&plan)
	c := model.common()
	timeout, timeoutDiags := c.Timeouts.Create(ctx, defaultDeploymentTimeout)
	diags.Append(timeoutDiags...)
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
	if !c.DeploymentMethod.IsUnknown() && !c.DeploymentMethod.IsNull() {
		method := apigen.AwsDeploymentMethod(c.DeploymentMethod.ValueString())
		body.DeploymentMethod = &method
	}
	if !c.ExternalIDKeyVersion.IsUnknown() && !c.ExternalIDKeyVersion.IsNull() {
		version := int(c.ExternalIDKeyVersion.ValueInt64())
		body.ExternalIDKeyVersion = &version
	}
	model.setTarget(ctx, &body, diags)
	if diags.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var result *client.AwsDeploymentResult
	outcome, err := awsVerification.run(ctx, func(ctx context.Context) error {
		var callErr error
		result, callErr = r.data.Client.CreateAwsDeployment(ctx, body, idempotencyKey())
		return callErr
	})
	if err != nil {
		r.addWriteError(diags, "create", model.targetLabel(), outcome, err)
		return
	}
	r.writeState(ctx, model, result.Deployment, diags)
	diags.Append(resp.State.Set(ctx, &plan)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	diags.AddWarning("Act verified the role", proofOfLife(model.targetLabel(), result.Deployment, outcome))
	addDeploymentWarnings(diags, result.Deployment)
}

func (r *awsDeploymentResource[M, P]) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	diags := &resp.Diagnostics
	var state M
	diags.Append(req.State.Get(ctx, &state)...)
	if diags.HasError() {
		return
	}
	model := P(&state)
	c := model.common()
	result, err := r.data.Client.GetAwsDeployment(ctx, c.ID.ValueString())
	if err != nil {
		diags.AddError("Reading the "+r.kind.title+" deployment failed", err.Error())
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	if !r.scopeMatches(result.Deployment) {
		diags.AddError("Wrong deployment type", fmt.Sprintf("Deployment %s %s", c.ID.ValueString(), r.kind.wrongScopeMessage))
		return
	}
	r.writeState(ctx, model, result.Deployment, diags)
	if c.ReverifyOnFailure.IsNull() {
		c.ReverifyOnFailure = types.BoolValue(true)
	}
	diags.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	if result.Deployment.Status == apigen.DeploymentStatusFailed {
		next := "The next apply asks Act to verify it again."
		if !c.ReverifyOnFailure.ValueBool() {
			next = "reverify_on_failure is false, so Terraform does not verify it again."
		}
		diags.AddWarning(
			"The "+r.kind.title+" deployment is failing",
			fmt.Sprintf("Act cannot use the role of %s: %s %s. Fix the role, for example by applying the configuration that creates it. %s", model.targetLabel(), derefString(result.Deployment.ErrorCode), derefString(result.Deployment.ErrorMessage), next),
		)
	}
}

func (r *awsDeploymentResource[M, P]) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	diags := &resp.Diagnostics
	var plan, state M
	diags.Append(req.Plan.Get(ctx, &plan)...)
	diags.Append(req.State.Get(ctx, &state)...)
	if diags.HasError() {
		return
	}
	model, prior := P(&plan), P(&state)
	next, current := model.common(), prior.common()
	timeout, timeoutDiags := next.Timeouts.Update(ctx, defaultDeploymentTimeout)
	diags.Append(timeoutDiags...)
	patch := r.buildPatch(ctx, model, prior, diags)
	if diags.HasError() {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	id := current.ID.ValueString()
	etag := privateString(ctx, req.Private, privateETag)
	var result *client.AwsDeploymentResult
	outcome := verificationOutcome{}
	call := func(action string, do func(ctx context.Context, etag string) (*client.AwsDeploymentResult, error)) bool {
		var err error
		outcome, err = awsVerification.run(ctx, func(ctx context.Context) error {
			var callErr error
			result, callErr = do(ctx, etag)
			if client.IsStatus(callErr, http.StatusPreconditionFailed) {
				fresh, ok := r.refreshETag(ctx, id, prior, diags)
				if !ok {
					return callErr
				}
				etag = fresh
				result, callErr = do(ctx, etag)
			}
			return callErr
		})
		if err != nil {
			if !diags.HasError() {
				r.addWriteError(diags, action, model.targetLabel(), outcome, err)
			}
			return false
		}
		etag = result.ETag
		return true
	}
	if len(patch) > 0 && !call("update", func(ctx context.Context, etag string) (*client.AwsDeploymentResult, error) {
		return r.data.Client.UpdateAwsDeployment(ctx, id, etag, patch)
	}) {
		return
	}
	if current.ExternalIDSource.ValueString() == externalIDLegacy && next.ExternalIDSource.ValueString() == externalIDDerived {
		if !call("rotate the external ID of", func(ctx context.Context, etag string) (*client.AwsDeploymentResult, error) {
			return r.data.Client.RotateAwsExternalID(ctx, id, etag)
		}) {
			return
		}
	}
	healing := current.Status.ValueString() == string(apigen.DeploymentStatusFailed) && next.ReverifyOnFailure.ValueBool()
	if healing && (result == nil || result.Deployment.Status != apigen.DeploymentStatusActive) {
		if !call("verify", func(ctx context.Context, etag string) (*client.AwsDeploymentResult, error) {
			return r.data.Client.VerifyAwsDeployment(ctx, id, etag)
		}) {
			return
		}
		diags.AddWarning("Act verified the role again", proofOfLife(model.targetLabel(), result.Deployment, outcome))
	}
	if result == nil {
		fresh, err := r.data.Client.GetAwsDeployment(ctx, id)
		if err != nil || fresh == nil {
			diags.AddError("Reading the "+r.kind.title+" deployment failed", fmt.Sprintf("Deployment %s: %v", id, err))
			return
		}
		result = fresh
	}
	r.writeState(ctx, model, result.Deployment, diags)
	diags.Append(resp.State.Set(ctx, &plan)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, diags)
	addDeploymentWarnings(diags, result.Deployment)
}

func (r *awsDeploymentResource[M, P]) refreshETag(ctx context.Context, id string, prior P, diags *diag.Diagnostics) (string, bool) {
	fresh, err := r.data.Client.GetAwsDeployment(ctx, id)
	if err != nil || fresh == nil {
		return "", false
	}
	remote := *prior
	copied := P(&remote)
	r.writeState(ctx, copied, fresh.Deployment, diags)
	if !sameIntent(copied.common(), prior.common()) || !copied.sameTarget(prior) {
		diags.AddError(
			"The "+r.kind.title+" deployment changed in Act",
			fmt.Sprintf("Someone changed deployment %s since Terraform last read it, so nothing was sent. Run terraform apply again to plan against the current settings.", id),
		)
		return "", false
	}
	return fresh.ETag, true
}

func (r *awsDeploymentResource[M, P]) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	diags := &resp.Diagnostics
	var state M
	diags.Append(req.State.Get(ctx, &state)...)
	if diags.HasError() {
		return
	}
	model := P(&state)
	id := model.common().ID.ValueString()
	cleanup, err := r.data.Client.DeleteAwsDeployment(ctx, id)
	if err != nil {
		var apiErr *client.APIError
		if asAPIError(err, &apiErr) && apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeDeletionProtected) {
			diags.AddError("The "+r.kind.title+" deployment has deletion protection", fmt.Sprintf("Act refused to delete %s. Set deletion_protection = false and apply before you destroy it.", id))
			return
		}
		diags.AddError("Disconnecting the "+r.kind.title+" deployment failed", err.Error())
		return
	}
	if len(cleanup) > 0 {
		lines := make([]string, 0, len(cleanup))
		for _, item := range cleanup {
			lines = append(lines, "- "+item.Resource+": "+item.Description)
		}
		diags.AddWarning("Act disconnected "+model.targetLabel(), "Act stopped scanning and deleted the credentials it held. These still exist in AWS:\n\n"+strings.Join(lines, "\n"))
	}
}

func (r *awsDeploymentResource[M, P]) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if !uuidPattern.MatchString(id) {
		if !r.kind.importKey(id) {
			resp.Diagnostics.AddError("Invalid import ID", "Use "+r.kind.importFormats+".")
			return
		}
		cloud := apigen.CloudAws
		items, err := r.data.Client.ListDeployments(ctx, client.DeploymentFilter{Cloud: &cloud, Target: &id})
		if err != nil {
			resp.Diagnostics.AddError("Listing deployments failed", err.Error())
			return
		}
		matches := []string{}
		for _, item := range items {
			if item.Scope == r.kind.scope {
				matches = append(matches, item.ID)
			}
		}
		switch len(matches) {
		case 0:
			resp.Diagnostics.AddError("No deployment to import", fmt.Sprintf("This tenant has no AWS %s deployment for %s.", r.kind.scope, id))
			return
		case 1:
			id = matches[0]
		default:
			resp.Diagnostics.AddError("More than one deployment matches", fmt.Sprintf("Deployments %s all cover %s. Import one by its ID.", strings.Join(matches, ", "), id))
			return
		}
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
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
	c.RoleArn = types.StringValue(item.RoleArn)
	c.Name = types.StringValue(item.Name)
	c.Tags = nullableStringMap(ctx, item.Tags, c.Tags, diags)
	c.AllowedRegions = nullableStringSet(ctx, item.AllowedRegions, diags)
	capabilities := make([]string, 0, len(item.DisabledCapabilities))
	for _, capability := range item.DisabledCapabilities {
		capabilities = append(capabilities, string(capability))
	}
	c.DisabledCapabilities = stringSet(ctx, capabilities, diags)
	c.DeploymentMethod = types.StringNull()
	if item.DeploymentMethod != nil {
		c.DeploymentMethod = types.StringValue(string(*item.DeploymentMethod))
	}
	c.DeletionProtection = types.BoolValue(item.DeletionProtection)
	c.ExternalIDKeyVersion = types.Int64Value(int64(item.ExternalIDKeyVersion))
	c.ExternalID = types.StringValue(item.ExternalID)
	c.ExternalIDSource = types.StringValue(string(item.ExternalIDSource))
	c.Status = types.StringValue(string(item.Status))
	c.ErrorCode = types.StringPointerValue(item.ErrorCode)
	c.ErrorMessage = types.StringPointerValue(item.ErrorMessage)
	c.UpdateAvailable = types.BoolValue(item.UpdateAvailable)
	c.DeployedVersion = types.StringPointerValue(item.DeployedVersion)
	c.CreatedAt = types.StringValue(item.CreatedAt.UTC().Format(time.RFC3339))
	c.ConsoleURL = types.StringValue(item.ConsoleURL)
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
	if !next.DeploymentMethod.IsUnknown() && !next.DeploymentMethod.Equal(current.DeploymentMethod) {
		patch["deploymentMethod"] = next.DeploymentMethod.ValueString()
	}
	if !next.DeletionProtection.IsUnknown() && !next.DeletionProtection.Equal(current.DeletionProtection) {
		patch["deletionProtection"] = next.DeletionProtection.ValueBool()
	}
	model.patchTarget(ctx, prior, patch, diags)
	return patch
}

func (r *awsDeploymentResource[M, P]) addWriteError(diags *diag.Diagnostics, action, target string, outcome verificationOutcome, err error) {
	summary := fmt.Sprintf("Could not %s the %s deployment", action, r.kind.title)
	var apiErr *client.APIError
	if !asAPIError(err, &apiErr) {
		diags.AddError(summary, err.Error())
		return
	}
	switch {
	case apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeAlreadyExists):
		existing := apiErr.Detail("deploymentId")
		if existing == "" {
			existing = target
		}
		diags.AddError(summary, fmt.Sprintf("Act already has a deployment for %s. Terraform does not take it over silently. Import it instead:\n\nimport {\n  to = %s.<name>\n  id = %q\n}", target, r.typeName(), existing))
	case apiErr.Code == codeVerificationFail:
		failure, _ := asVerificationFailure(err)
		detail := verificationDetail(failure, outcome)
		if failure.attribute == "roleArn" || failure.attribute == "" {
			diags.AddAttributeError(path.Root("role_arn"), summary, detail)
			return
		}
		diags.AddError(summary, detail)
	case apiErr.Status == http.StatusPreconditionFailed:
		diags.AddError(summary, "The deployment changed in Act since Terraform last read it. Run terraform apply again to plan against the current settings.")
	case apiErr.Code == string(apigen.ErrorEnvelopeErrorCodeInvalidRequest):
		if attribute := wireAttribute(apiErr.Detail("attribute")); attribute != "" {
			diags.AddAttributeError(path.Root(attribute), summary, fmt.Sprintf("Act rejected %s: %s.", attribute, apiErr.Detail("reason")))
			return
		}
		diags.AddError(summary, err.Error())
	default:
		diags.AddError(summary, err.Error())
	}
}

func verificationDetail(failure *verificationFailure, outcome verificationOutcome) string {
	code := failure.cloudErrorCode
	if code == "" {
		code = failure.err.Message
	}
	detail := "Act could not use the role: " + code + "."
	if failure.hint != "" {
		detail += " " + failure.hint
	}
	switch {
	case failure.retryClass == retryClassPropagation && outcome.timedOut:
		detail += fmt.Sprintf(" Act kept trying for %s (%d attempts) while AWS propagated the role, then gave up. Nothing was stored. Apply again, or raise timeouts if the role takes longer to propagate.", outcome.elapsed.Round(time.Second), outcome.attempts)
	case outcome.attempts > 1:
		detail += fmt.Sprintf(" Act got the same answer %d times, so this needs a fix on the AWS side. Nothing was stored.", outcome.attempts)
	default:
		detail += " Nothing was stored."
	}
	return detail
}

func proofOfLife(target string, item apigen.AwsDeployment, outcome verificationOutcome) string {
	message := fmt.Sprintf("Connected. Act started the first scan of %s; open %s", target, item.ConsoleURL)
	if outcome.attempts > 1 {
		message += fmt.Sprintf("\n\nVerified after %s and %d attempts while AWS propagated the role.", outcome.elapsed.Round(time.Second), outcome.attempts)
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

func wireAttribute(name string) string {
	return wireAttributes[name]
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
