package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

var (
	cloudNames            = []string{string(apigen.CloudAws), string(apigen.CloudAzure), string(apigen.CloudGcp)}
	deploymentStatusNames = []string{string(apigen.DeploymentStatusActive), string(apigen.DeploymentStatusFailed), string(apigen.DeploymentStatusPendingConsent)}
	memberStatusNames     = []string{
		string(apigen.MemberAccountStatusConnected),
		string(apigen.MemberAccountStatusPending),
		string(apigen.MemberAccountStatusFailed),
		string(apigen.MemberAccountStatusExcluded),
	}
	variantPattern = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

type actDataSource struct {
	data *ProviderData
}

func (d *actDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	data, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", "The provider passed data of an unexpected type.")
		return
	}
	d.data = data
}

type awsOnboardingDataSource struct{ actDataSource }

type existingDeploymentModel struct {
	ID         types.String `tfsdk:"id"`
	Status     types.String `tfsdk:"status"`
	CreatedVia types.String `tfsdk:"created_via"`
}

type moduleVersionModel struct {
	Version           types.String `tfsdk:"version"`
	Sha256            types.String `tfsdk:"sha256"`
	PermissionsHash   types.String `tfsdk:"permissions_hash"`
	DeploymentVersion types.String `tfsdk:"deployment_version"`
}

type awsOnboardingModel struct {
	AccountID                    types.String             `tfsdk:"account_id"`
	OrganizationID               types.String             `tfsdk:"organization_id"`
	Variant                      types.String             `tfsdk:"variant"`
	DeploymentID                 types.String             `tfsdk:"deployment_id"`
	ExistingDeployment           *existingDeploymentModel `tfsdk:"existing_deployment"`
	ActPrincipalArn              types.String             `tfsdk:"act_principal_arn"`
	DeprecatedPrincipalArns      []types.String           `tfsdk:"deprecated_principal_arns"`
	ExternalID                   types.String             `tfsdk:"external_id"`
	ExternalIDSource             types.String             `tfsdk:"external_id_source"`
	TargetExternalID             types.String             `tfsdk:"target_external_id"`
	ExternalIDKeyVersion         types.Int64              `tfsdk:"external_id_key_version"`
	RoleName                     types.String             `tfsdk:"role_name"`
	RoleArn                      types.String             `tfsdk:"role_arn"`
	AssumeRolePolicyJSON         types.String             `tfsdk:"assume_role_policy_json"`
	CustomPolicyDocuments        map[string]types.String  `tfsdk:"custom_policy_documents"`
	ManagedPolicyArns            []types.String           `tfsdk:"managed_policy_arns"`
	MemberRoleName               types.String             `tfsdk:"member_role_name"`
	MemberRolePath               types.String             `tfsdk:"member_role_path"`
	CloudformationTemplateURL    types.String             `tfsdk:"cloudformation_template_url"`
	CloudformationTemplateSha256 types.String             `tfsdk:"cloudformation_template_sha256"`
	ModuleSource                 types.String             `tfsdk:"module_source"`
	ModuleVersion                types.String             `tfsdk:"module_version"`
	ModuleSha256                 types.String             `tfsdk:"module_sha256"`
	PermissionsHash              types.String             `tfsdk:"permissions_hash"`
	DeploymentVersion            types.String             `tfsdk:"deployment_version"`
	ModuleVersions               []moduleVersionModel     `tfsdk:"module_versions"`
}

var _ datasource.DataSourceWithConfigValidators = (*awsOnboardingDataSource)(nil)

func NewAwsOnboardingParametersDataSource() datasource.DataSource {
	return &awsOnboardingDataSource{}
}

func (d *awsOnboardingDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_aws_onboarding_parameters"
}

func computedString(description string) schema.StringAttribute {
	return schema.StringAttribute{MarkdownDescription: description, Computed: true}
}

func computedStrings(description string) schema.ListAttribute {
	return schema.ListAttribute{MarkdownDescription: description, ElementType: types.StringType, Computed: true}
}

func (d *awsOnboardingDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The values an AWS account or organization needs before it can connect to Act: the deployment ID, the Act principal to trust, the external ID and the role name. A read, it creates nothing. For a target that already has a deployment, every value is the deployment's own.",
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{
				MarkdownDescription: "The 12-digit AWS account to connect. Set this or `organization_id`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(awsAccountIDPattern, "must be a 12-digit AWS account ID")},
			},
			"organization_id": schema.StringAttribute{
				MarkdownDescription: "The AWS organization to connect, `o-...`. Set this or `account_id`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(awsOrgIDPattern, "must be an AWS organization ID")},
			},
			"variant": schema.StringAttribute{
				MarkdownDescription: "Set only for a second deployment over the same target: up to 32 lowercase letters, digits and hyphens.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(variantPattern, "must be 1 to 32 lowercase letters, digits or hyphens")},
			},
			"deployment_id": computedString("The deployment ID Act issued for this target. Pass it to `deployment_id` of the deployment resource."),
			"existing_deployment": schema.SingleNestedAttribute{
				MarkdownDescription: "The deployment that already covers this target, for example one created in the Act console. Null when there is none. Import it rather than creating another.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"id":          computedString("The deployment ID."),
					"status":      computedString("`active`, `failed` or `pending_consent`."),
					"created_via": computedString("`ui` or `api`. Null when Act does not know."),
				},
			},
			"act_principal_arn":         computedString("The Act principal the role's trust policy allows."),
			"deprecated_principal_arns": computedStrings("Act principals that are being retired. Trust them too until they expire, so a rotation never breaks the connection."),
			"external_id":               computedString("The external ID the role's trust policy must require. Not a secret."),
			"external_id_source":        computedString("`derived` or `legacy`."),
			"target_external_id":        computedString("The derived external ID. It differs from `external_id` only for a deployment that still uses a legacy one."),
			"external_id_key_version": schema.Int64Attribute{
				MarkdownDescription: "The key version of the external ID. Pass it to `external_id_key_version` of the deployment resource.",
				Computed:            true,
			},
			"role_name":                      computedString("The name to give the role."),
			"role_arn":                       computedString("The role's ARN. Known at plan time for an account, null for an organization."),
			"assume_role_policy_json":        computedString("The role's trust policy as JSON, for configurations that do not use the Act module."),
			"custom_policy_documents":        schema.MapAttribute{MarkdownDescription: "Policy documents to attach to the role, by policy name, for configurations that do not use the Act module.", ElementType: types.StringType, Computed: true},
			"managed_policy_arns":            computedStrings("AWS managed policies to attach to the role, for configurations that do not use the Act module."),
			"member_role_name":               computedString("The role name for member accounts of an organization."),
			"member_role_path":               computedString("The IAM path for member roles."),
			"cloudformation_template_url":    computedString("A versioned CloudFormation template for the member roles. It never changes after release."),
			"cloudformation_template_sha256": computedString("The SHA-256 of the CloudFormation template."),
			"module_source":                  computedString("The registry address of the Act module for AWS."),
			"module_version":                 computedString("The module version Act recommends for this tenant."),
			"module_sha256":                  computedString("The SHA-256 of the recommended module release."),
			"permissions_hash":               computedString("A hash of the permissions the recommended module grants."),
			"deployment_version":             computedString("The role version the recommended module deploys."),
			"module_versions": schema.ListNestedAttribute{
				MarkdownDescription: "Every module version Act accepts today.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"version":            computedString("The module version."),
					"sha256":             computedString("The SHA-256 of the release."),
					"permissions_hash":   computedString("A hash of the permissions it grants."),
					"deployment_version": computedString("The role version it deploys."),
				}},
			},
		},
	}
}

func (d *awsOnboardingDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{datasourcevalidator.ExactlyOneOf(path.MatchRoot("account_id"), path.MatchRoot("organization_id"))}
}

func (d *awsOnboardingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model awsOnboardingModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	params := apigen.GetAwsOnboardingParams{
		AccountID:      knownString(model.AccountID),
		OrganizationID: knownString(model.OrganizationID),
		Variant:        knownString(model.Variant),
	}
	values, err := d.data.Client.GetAwsOnboarding(ctx, params)
	if err != nil {
		resp.Diagnostics.AddError("Reading the AWS onboarding values failed", err.Error())
		return
	}
	model.DeploymentID = types.StringValue(values.DeploymentID)
	model.ExistingDeployment = nil
	if existing := values.ExistingDeployment; existing != nil {
		model.ExistingDeployment = &existingDeploymentModel{
			ID:         types.StringValue(existing.ID),
			Status:     types.StringValue(string(existing.Status)),
			CreatedVia: types.StringNull(),
		}
		if existing.CreatedVia != nil {
			model.ExistingDeployment.CreatedVia = types.StringValue(string(*existing.CreatedVia))
		}
	}
	model.ActPrincipalArn = types.StringValue(values.ActPrincipalArn)
	model.DeprecatedPrincipalArns = []types.String{}
	for _, principal := range values.DeprecatedPrincipals {
		model.DeprecatedPrincipalArns = append(model.DeprecatedPrincipalArns, types.StringValue(principal.Arn))
	}
	model.ExternalID = types.StringValue(values.ExternalID)
	model.ExternalIDSource = types.StringValue(string(values.ExternalIDSource))
	model.TargetExternalID = types.StringValue(values.TargetExternalID)
	model.ExternalIDKeyVersion = types.Int64Value(int64(values.ExternalIDKeyVersion))
	model.RoleName = types.StringValue(values.RoleName)
	model.RoleArn = types.StringPointerValue(values.RoleArn)
	model.AssumeRolePolicyJSON = types.StringValue(values.AssumeRolePolicyJSON)
	model.CustomPolicyDocuments = map[string]types.String{}
	for name, document := range values.CustomPolicyDocuments {
		model.CustomPolicyDocuments[name] = types.StringValue(document)
	}
	model.ManagedPolicyArns = stringValues(values.ManagedPolicyArns)
	model.MemberRoleName = types.StringValue(values.MemberRoleName)
	model.MemberRolePath = types.StringValue(values.MemberRolePath)
	model.CloudformationTemplateURL = types.StringValue(values.CloudformationTemplateURL)
	model.CloudformationTemplateSha256 = types.StringValue(values.CloudformationTemplateSha256)
	model.ModuleSource = types.StringValue(values.ModuleSource)
	model.ModuleVersion = types.StringValue(values.ModuleVersion)
	model.ModuleSha256 = types.StringValue(values.ModuleSha256)
	model.PermissionsHash = types.StringValue(values.PermissionsHash)
	model.DeploymentVersion = types.StringValue(values.DeploymentVersion)
	model.ModuleVersions = []moduleVersionModel{}
	for _, version := range values.ModuleVersions {
		model.ModuleVersions = append(model.ModuleVersions, moduleVersionModel{
			Version:           types.StringValue(version.Version),
			Sha256:            types.StringValue(version.Sha256),
			PermissionsHash:   types.StringValue(version.PermissionsHash),
			DeploymentVersion: types.StringValue(version.DeploymentVersion),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type deploymentSummaryModel struct {
	ID                 types.String            `tfsdk:"id"`
	Cloud              types.String            `tfsdk:"cloud"`
	Name               types.String            `tfsdk:"name"`
	Scope              types.String            `tfsdk:"scope"`
	Targets            []types.String          `tfsdk:"targets"`
	Status             types.String            `tfsdk:"status"`
	UpdateAvailable    types.Bool              `tfsdk:"update_available"`
	DeletionProtection types.Bool              `tfsdk:"deletion_protection"`
	Tags               map[string]types.String `tfsdk:"tags"`
	CreatedAt          types.String            `tfsdk:"created_at"`
}

func summaryAttributes(idDescription string) map[string]schema.Attribute {
	return map[string]schema.Attribute{
		"id":      computedString(idDescription),
		"cloud":   computedString("`aws`, `azure` or `gcp`."),
		"name":    computedString("The name Act shows."),
		"scope":   computedString("`account`, `organization`, `subscription`, `management_group` or `project`."),
		"targets": computedStrings("What the deployment covers: an account ID, or an organization ID with its root or organizational unit IDs."),
		"status":  computedString("`active`, `failed` or `pending_consent`."),
		"update_available": schema.BoolAttribute{
			MarkdownDescription: "True when the cloud side is older than the version Act recommends.",
			Computed:            true,
		},
		"deletion_protection": schema.BoolAttribute{MarkdownDescription: "Whether Act refuses to delete it.", Computed: true},
		"tags":                schema.MapAttribute{MarkdownDescription: "Act tags.", ElementType: types.StringType, Computed: true},
		"created_at":          computedString("When it was created, in RFC 3339."),
	}
}

func summaryModel(item apigen.DeploymentSummary) deploymentSummaryModel {
	tags := map[string]types.String{}
	for key, value := range item.Tags {
		tags[key] = types.StringValue(value)
	}
	return deploymentSummaryModel{
		ID:                 types.StringValue(item.ID),
		Cloud:              types.StringValue(string(item.Cloud)),
		Name:               types.StringValue(item.Name),
		Scope:              types.StringValue(string(item.Scope)),
		Targets:            stringValues(item.Targets),
		Status:             types.StringValue(string(item.Status)),
		UpdateAvailable:    types.BoolValue(item.UpdateAvailable),
		DeletionProtection: types.BoolValue(item.DeletionProtection),
		Tags:               tags,
		CreatedAt:          types.StringValue(item.CreatedAt.UTC().Format(time.RFC3339)),
	}
}

type deploymentDataSource struct{ actDataSource }

type deploymentLookupModel struct {
	deploymentSummaryModel
	Target types.String `tfsdk:"target"`
}

var _ datasource.DataSourceWithConfigValidators = (*deploymentDataSource)(nil)

func NewDeploymentDataSource() datasource.DataSource { return &deploymentDataSource{} }

func (d *deploymentDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_deployment"
}

func (d *deploymentDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attributes := summaryAttributes("")
	attributes["id"] = schema.StringAttribute{
		MarkdownDescription: "The deployment ID. Set this or `target`.",
		Optional:            true,
		Computed:            true,
		Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
	}
	attributes["target"] = schema.StringAttribute{
		MarkdownDescription: "Find the deployment that covers this target instead, such as a 12-digit AWS account ID or an organization ID. Set this or `id`. Exactly one deployment must match.",
		Optional:            true,
		Validators:          []validator.String{stringvalidator.LengthBetween(1, 128)},
	}
	attributes["cloud"] = schema.StringAttribute{
		MarkdownDescription: "`aws`, `azure` or `gcp`. Set it to narrow a `target` lookup.",
		Optional:            true,
		Computed:            true,
		Validators:          []validator.String{stringvalidator.OneOf(cloudNames...)},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "One deployment, by ID or by what it covers. Use it to read a deployment another workspace or the Act console manages.",
		Attributes:          attributes,
	}
}

func (d *deploymentDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("target"))}
}

func (d *deploymentDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model deploymentLookupModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	filter := client.DeploymentFilter{Target: knownString(model.Target)}
	if cloud := knownString(model.Cloud); cloud != nil {
		value := apigen.Cloud(*cloud)
		filter.Cloud = &value
	}
	items, err := d.data.Client.ListDeployments(ctx, filter)
	if err != nil {
		resp.Diagnostics.AddError("Listing deployments failed", err.Error())
		return
	}
	matches := []apigen.DeploymentSummary{}
	for _, item := range items {
		if model.ID.IsNull() || item.ID == model.ID.ValueString() {
			matches = append(matches, item)
		}
	}
	wanted := model.ID.ValueString()
	if wanted == "" {
		wanted = model.Target.ValueString()
	}
	switch len(matches) {
	case 0:
		resp.Diagnostics.AddError("Deployment not found", fmt.Sprintf("No deployment in this tenant matches %s.", wanted))
		return
	case 1:
	default:
		ids := make([]string, 0, len(matches))
		for _, item := range matches {
			ids = append(ids, item.ID)
		}
		resp.Diagnostics.AddError("More than one deployment matches", fmt.Sprintf("Deployments %s all cover %s. Look one up by id.", strings.Join(ids, ", "), wanted))
		return
	}
	model.deploymentSummaryModel = summaryModel(matches[0])
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type deploymentsDataSource struct{ actDataSource }

type deploymentsModel struct {
	Cloud       types.String             `tfsdk:"cloud"`
	Status      types.String             `tfsdk:"status"`
	Target      types.String             `tfsdk:"target"`
	Tags        map[string]types.String  `tfsdk:"tags"`
	IDs         []types.String           `tfsdk:"ids"`
	Deployments []deploymentSummaryModel `tfsdk:"deployments"`
}

func NewDeploymentsDataSource() datasource.DataSource { return &deploymentsDataSource{} }

func (d *deploymentsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_deployments"
}

func (d *deploymentsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The tenant's deployments, optionally filtered. Every filter you set must match.",
		Attributes: map[string]schema.Attribute{
			"cloud": schema.StringAttribute{
				MarkdownDescription: "Only deployments in this cloud: `aws`, `azure` or `gcp`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.OneOf(cloudNames...)},
			},
			"status": schema.StringAttribute{
				MarkdownDescription: "Only deployments with this status: `active`, `failed` or `pending_consent`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.OneOf(deploymentStatusNames...)},
			},
			"target": schema.StringAttribute{
				MarkdownDescription: "Only deployments that cover this target, such as an AWS account ID.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 128)},
			},
			"tags": schema.MapAttribute{
				MarkdownDescription: "Only deployments that carry all of these Act tags.",
				ElementType:         types.StringType,
				Optional:            true,
			},
			"ids": computedStrings("The IDs of the matching deployments."),
			"deployments": schema.ListNestedAttribute{
				MarkdownDescription: "The matching deployments.",
				Computed:            true,
				NestedObject:        schema.NestedAttributeObject{Attributes: summaryAttributes("The deployment ID.")},
			},
		},
	}
}

func (d *deploymentsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model deploymentsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	filter := client.DeploymentFilter{Target: knownString(model.Target)}
	if cloud := knownString(model.Cloud); cloud != nil {
		value := apigen.Cloud(*cloud)
		filter.Cloud = &value
	}
	if status := knownString(model.Status); status != nil {
		value := apigen.DeploymentStatus(*status)
		filter.Status = &value
	}
	if len(model.Tags) > 0 {
		filter.Tags = map[string]string{}
		for key, value := range model.Tags {
			filter.Tags[key] = value.ValueString()
		}
	}
	items, err := d.data.Client.ListDeployments(ctx, filter)
	if err != nil {
		resp.Diagnostics.AddError("Listing deployments failed", err.Error())
		return
	}
	model.IDs = []types.String{}
	model.Deployments = []deploymentSummaryModel{}
	for _, item := range items {
		model.IDs = append(model.IDs, types.StringValue(item.ID))
		model.Deployments = append(model.Deployments, summaryModel(item))
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type deploymentCoverageDataSource struct{ actDataSource }

type failedAccountModel struct {
	AccountID    types.String `tfsdk:"account_id"`
	ErrorCode    types.String `tfsdk:"error_code"`
	Cause        types.String `tfsdk:"cause"`
	FailingSince types.String `tfsdk:"failing_since"`
}

type deploymentCoverageModel struct {
	DeploymentID      types.String         `tfsdk:"deployment_id"`
	AccountsExpected  types.Int64          `tfsdk:"accounts_expected"`
	AccountsConnected types.Int64          `tfsdk:"accounts_connected"`
	AccountsFailed    types.Int64          `tfsdk:"accounts_failed"`
	AccountsPending   types.Int64          `tfsdk:"accounts_pending"`
	DiscoveryState    types.String         `tfsdk:"discovery_state"`
	LastDiscoveryAt   types.String         `tfsdk:"last_discovery_at"`
	FailedAccounts    []failedAccountModel `tfsdk:"failed_accounts"`
}

func NewDeploymentCoverageDataSource() datasource.DataSource { return &deploymentCoverageDataSource{} }

func (d *deploymentCoverageDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_deployment_coverage"
}

func computedCount(description string) schema.Int64Attribute {
	return schema.Int64Attribute{MarkdownDescription: description, Computed: true}
}

func (d *deploymentCoverageDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "How many of a deployment's accounts Act reaches right now. Use it in a `check` block: it changes as Act discovers and scans accounts, so the deployment resources never store it.",
		Attributes: map[string]schema.Attribute{
			"deployment_id": schema.StringAttribute{
				MarkdownDescription: "The deployment ID.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"accounts_expected":  computedCount("Accounts Act expects to reach, excluded accounts left out."),
			"accounts_connected": computedCount("Accounts Act reaches."),
			"accounts_failed":    computedCount("Accounts Act cannot reach."),
			"accounts_pending":   computedCount("Accounts Act has not tried yet."),
			"discovery_state":    computedString("`pending`, `running` or `complete`."),
			"last_discovery_at":  computedString("When Act last listed the accounts, in RFC 3339. Null before the first run."),
			"failed_accounts": schema.ListNestedAttribute{
				MarkdownDescription: "The accounts Act cannot reach.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"account_id":    computedString("The account ID."),
					"error_code":    computedString("Why Act cannot reach it."),
					"cause":         computedString("What Act saw. Null when unknown."),
					"failing_since": computedString("When it started failing, in RFC 3339."),
				}},
			},
		},
	}
}

func (d *deploymentCoverageDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model deploymentCoverageModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	coverage, err := d.data.Client.GetDeploymentCoverage(ctx, model.DeploymentID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading the deployment coverage failed", err.Error())
		return
	}
	model.AccountsExpected = types.Int64Value(int64(coverage.AccountsExpected))
	model.AccountsConnected = types.Int64Value(int64(coverage.AccountsConnected))
	model.AccountsFailed = types.Int64Value(int64(coverage.AccountsFailed))
	model.AccountsPending = types.Int64Value(int64(coverage.AccountsPending))
	model.DiscoveryState = types.StringValue(string(coverage.DiscoveryState))
	model.LastDiscoveryAt = types.StringNull()
	if coverage.LastDiscoveryAt != nil {
		model.LastDiscoveryAt = types.StringValue(coverage.LastDiscoveryAt.UTC().Format(time.RFC3339))
	}
	model.FailedAccounts = []failedAccountModel{}
	for _, failed := range coverage.FailedAccounts {
		model.FailedAccounts = append(model.FailedAccounts, failedAccountModel{
			AccountID:    types.StringValue(failed.AccountID),
			ErrorCode:    types.StringValue(failed.ErrorCode),
			Cause:        types.StringPointerValue(failed.Cause),
			FailingSince: types.StringValue(failed.FailingSince.UTC().Format(time.RFC3339)),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type deploymentAccountsDataSource struct{ actDataSource }

type memberAccountModel struct {
	AccountID types.String `tfsdk:"account_id"`
	Name      types.String `tfsdk:"name"`
	Status    types.String `tfsdk:"status"`
	ErrorCode types.String `tfsdk:"error_code"`
}

type deploymentAccountsModel struct {
	DeploymentID types.String         `tfsdk:"deployment_id"`
	Status       types.String         `tfsdk:"status"`
	AccountIDs   []types.String       `tfsdk:"account_ids"`
	Accounts     []memberAccountModel `tfsdk:"accounts"`
}

func NewDeploymentAccountsDataSource() datasource.DataSource { return &deploymentAccountsDataSource{} }

func (d *deploymentAccountsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_deployment_accounts"
}

func (d *deploymentAccountsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The member accounts a deployment resolves to, with each one's status. For an account deployment it is the account itself.",
		Attributes: map[string]schema.Attribute{
			"deployment_id": schema.StringAttribute{
				MarkdownDescription: "The deployment ID.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"status": schema.StringAttribute{
				MarkdownDescription: "Only accounts with this status: `connected`, `pending`, `failed` or `excluded`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.OneOf(memberStatusNames...)},
			},
			"account_ids": computedStrings("The IDs of the matching accounts."),
			"accounts": schema.ListNestedAttribute{
				MarkdownDescription: "The matching accounts.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"account_id": computedString("The account ID."),
					"name":       computedString("The account name. Null when Act does not know it."),
					"status":     computedString("`connected`, `pending`, `failed` or `excluded`."),
					"error_code": computedString("Why Act cannot reach it. Null unless failed."),
				}},
			},
		},
	}
}

func (d *deploymentAccountsDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model deploymentAccountsModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var status *apigen.MemberAccountStatus
	if value := knownString(model.Status); value != nil {
		filter := apigen.MemberAccountStatus(*value)
		status = &filter
	}
	accounts, err := d.data.Client.ListDeploymentAccounts(ctx, model.DeploymentID.ValueString(), status)
	if err != nil {
		resp.Diagnostics.AddError("Listing the deployment's accounts failed", err.Error())
		return
	}
	model.AccountIDs = []types.String{}
	model.Accounts = []memberAccountModel{}
	for _, account := range accounts {
		model.AccountIDs = append(model.AccountIDs, types.StringValue(account.AccountID))
		model.Accounts = append(model.Accounts, memberAccountModel{
			AccountID: types.StringValue(account.AccountID),
			Name:      types.StringPointerValue(account.Name),
			Status:    types.StringValue(string(account.Status)),
			ErrorCode: types.StringPointerValue(account.ErrorCode),
		})
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func stringValues(values []string) []types.String {
	out := make([]types.String, 0, len(values))
	for _, value := range values {
		out = append(out, types.StringValue(value))
	}
	return out
}
