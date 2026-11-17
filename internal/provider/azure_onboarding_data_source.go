package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type azureOnboardingDataSource struct{ actDataSource }

type azureOnboardingModel struct {
	DirectoryID             types.String             `tfsdk:"directory_id"`
	SubscriptionID          types.String             `tfsdk:"subscription_id"`
	ManagementGroupID       types.String             `tfsdk:"management_group_id"`
	Variant                 types.String             `tfsdk:"variant"`
	DeploymentID            types.String             `tfsdk:"deployment_id"`
	ExistingDeployment      *existingDeploymentModel `tfsdk:"existing_deployment"`
	AzureTenantID           types.String             `tfsdk:"azure_tenant_id"`
	TenantConsented         types.Bool               `tfsdk:"tenant_consented"`
	AdminConsentURL         types.String             `tfsdk:"admin_consent_url"`
	ActAppClientID          types.String             `tfsdk:"act_app_client_id"`
	ActServicePrincipalID   types.String             `tfsdk:"act_service_principal_id"`
	CustomRoleName          types.String             `tfsdk:"custom_role_name"`
	CustomRoleActions       []types.String           `tfsdk:"custom_role_actions"`
	BindingMarker           types.String             `tfsdk:"binding_marker"`
	RequiredBuiltinRoleIDs  []types.String           `tfsdk:"required_builtin_role_ids"`
	RequiredGraphAppRoleIDs []types.String           `tfsdk:"required_graph_app_role_ids"`
	ModuleSource            types.String             `tfsdk:"module_source"`
	ModuleVersion           types.String             `tfsdk:"module_version"`
	ModuleSha256            types.String             `tfsdk:"module_sha256"`
	PermissionsHash         types.String             `tfsdk:"permissions_hash"`
	DeploymentVersion       types.String             `tfsdk:"deployment_version"`
	ModuleVersions          []moduleVersionModel     `tfsdk:"module_versions"`
}

var _ datasource.DataSourceWithConfigValidators = (*azureOnboardingDataSource)(nil)

func NewAzureOnboardingParametersDataSource() datasource.DataSource {
	return &azureOnboardingDataSource{}
}

func (d *azureOnboardingDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_azure_onboarding_parameters"
}

func (d *azureOnboardingDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The values an Azure subscription or management group needs before it can connect to Act: the deployment ID, Act's app and service principal, the custom role to create and the roles to assign. A read, it creates nothing. For a target that already has a deployment, every value is the deployment's own.",
		Attributes: map[string]schema.Attribute{
			"directory_id": schema.StringAttribute{
				MarkdownDescription: "The Entra directory (Azure tenant) that owns the subscription or management group, a lowercase UUID.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"subscription_id": schema.StringAttribute{
				MarkdownDescription: "The Azure subscription to connect, a lowercase UUID. Set this or `management_group_id`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"management_group_id": schema.StringAttribute{
				MarkdownDescription: "The Azure management group to connect. Set this or `subscription_id`.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(azureManagementGroupPattern, "must be an Azure management group ID: 1 to 90 letters, digits, or _ ( ) . -")},
			},
			"variant": schema.StringAttribute{
				MarkdownDescription: "Set only for a second deployment over the same target: up to 32 lowercase letters, digits and hyphens.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(variantPattern, "must be 1 to 32 lowercase letters, digits or hyphens")},
			},
			"deployment_id": computedString("The deployment ID Act issued for this target. Pass it to `deployment_id` of `act_azure_deployment`."),
			"existing_deployment": schema.SingleNestedAttribute{
				MarkdownDescription: "The deployment that already covers this target, for example one created in the Act console. Null when there is none. Import it rather than creating another.",
				Computed:            true,
				Attributes: map[string]schema.Attribute{
					"id":          computedString("The deployment ID."),
					"status":      computedString("`active`, `failed` or `pending_consent`."),
					"created_via": computedString("`ui` or `api`. Null when Act does not know."),
				},
			},
			"azure_tenant_id": computedString("The Entra directory ID Act records for the target. Pass it to `azure_tenant_id` of `act_azure_deployment`."),
			"tenant_consented": schema.BoolAttribute{
				MarkdownDescription: "Whether an Entra admin has already approved Act in this directory. While false, a new deployment is stored as `pending_consent`.",
				Computed:            true,
			},
			"admin_consent_url":           computedString("The link an Entra admin opens once to approve Act in the directory. Reading it changes nothing; only opening it and approving does."),
			"act_app_client_id":           computedString("The client ID of Act's multi-tenant app."),
			"act_service_principal_id":    computedString("The object ID of Act's service principal in the directory. Null until an Entra admin approves Act, or until the service principal is created another way."),
			"custom_role_name":            computedString("The name to give the custom role that holds the actions Act needs."),
			"custom_role_actions":         computedStrings("The actions of the custom role."),
			"binding_marker":              computedString("Text to put in the custom role's description. Act checks it to tie the role to this deployment. Not a secret."),
			"required_builtin_role_ids":   computedStrings("The Azure built-in role definitions to assign to Act's service principal at the target, as role definition GUIDs."),
			"required_graph_app_role_ids": computedStrings("The Microsoft Graph app roles Act's service principal needs for `include_entra_id`, as app role GUIDs."),
			"module_source":               computedString("The registry address of the Act module for Azure. Null until Act publishes versioned modules and templates."),
			"module_version":              computedString("The module version Act recommends for this tenant. Null until Act publishes versioned modules and templates."),
			"module_sha256":               computedString("The SHA-256 of the recommended module release. Null until Act publishes versioned modules and templates."),
			"permissions_hash":            computedString("A hash of the permissions the recommended module grants. Null until Act publishes versioned modules and templates."),
			"deployment_version":          computedString("The version the recommended module deploys. Null until Act publishes versioned modules and templates."),
			"module_versions": schema.ListNestedAttribute{
				MarkdownDescription: "Every module version Act accepts today. Null until Act publishes versioned modules and templates.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"version":            computedString("The module version."),
					"sha256":             computedString("The SHA-256 of the release."),
					"permissions_hash":   computedString("A hash of the permissions it grants."),
					"deployment_version": computedString("The version it deploys."),
				}},
			},
		},
	}
}

func (d *azureOnboardingDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{datasourcevalidator.ExactlyOneOf(path.MatchRoot("subscription_id"), path.MatchRoot("management_group_id"))}
}

func (d *azureOnboardingDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model azureOnboardingModel
	if resp.Diagnostics.Append(req.Config.Get(ctx, &model)...); resp.Diagnostics.HasError() {
		return
	}
	params := apigen.GetAzureOnboardingParams{
		DirectoryID:       model.DirectoryID.ValueString(),
		SubscriptionID:    knownString(model.SubscriptionID),
		ManagementGroupID: knownString(model.ManagementGroupID),
		Variant:           knownString(model.Variant),
	}
	values, err := d.data.Client.GetAzureOnboarding(ctx, params)
	if err != nil {
		resp.Diagnostics.AddError("Reading the Azure onboarding values failed", err.Error())
		return
	}
	model.fillFrom(*values)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

func (m *azureOnboardingModel) fillFrom(values apigen.AzureOnboarding) {
	m.DeploymentID = types.StringValue(values.DeploymentID)
	m.ExistingDeployment = existingDeployment(values.ExistingDeployment)
	m.AzureTenantID = types.StringValue(values.AzureTenantID)
	m.TenantConsented = types.BoolValue(values.TenantConsented)
	m.AdminConsentURL = types.StringValue(values.AdminConsentURL)
	m.ActAppClientID = types.StringValue(values.ActAppClientID)
	m.ActServicePrincipalID = types.StringPointerValue(values.ActServicePrincipalID)
	m.CustomRoleName = types.StringValue(values.CustomRoleName)
	m.CustomRoleActions = typedStrings(values.CustomRoleActions)
	m.BindingMarker = types.StringValue(values.BindingMarker)
	m.RequiredBuiltinRoleIDs = typedStrings(values.RequiredBuiltinRoleIds)
	m.RequiredGraphAppRoleIDs = typedStrings(values.RequiredGraphAppRoleIds)
	m.ModuleSource = types.StringPointerValue(values.ModuleSource)
	m.ModuleVersion = types.StringPointerValue(values.ModuleVersion)
	m.ModuleSha256 = types.StringPointerValue(values.ModuleSha256)
	m.PermissionsHash = types.StringPointerValue(values.PermissionsHash)
	m.DeploymentVersion = types.StringPointerValue(values.DeploymentVersion)
	m.ModuleVersions = moduleVersions(values.ModuleVersions)
}
