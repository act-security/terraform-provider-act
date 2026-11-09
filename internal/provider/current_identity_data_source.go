package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ datasource.DataSourceWithConfigure = (*currentIdentityDataSource)(nil)

type currentIdentityDataSource struct {
	data *ProviderData
}

type currentIdentityModel struct {
	TenantID          types.String `tfsdk:"tenant_id"`
	TenantDisplayName types.String `tfsdk:"tenant_display_name"`
	Region            types.String `tfsdk:"region"`
	PrincipalKind     types.String `tfsdk:"principal_kind"`
	PrincipalID       types.String `tfsdk:"principal_id"`
	PrincipalName     types.String `tfsdk:"principal_name"`
	PrincipalRole     types.String `tfsdk:"principal_role"`
	TokenScope        types.String `tfsdk:"token_scope"`
	Scopes            types.List   `tfsdk:"scopes"`
	AuthMethod        types.String `tfsdk:"auth_method"`
	Phase             types.String `tfsdk:"phase"`
	TokenExpiresAt    types.String `tfsdk:"token_expires_at"`
	FederationIssuer  types.String `tfsdk:"federation_issuer"`
}

func NewCurrentIdentityDataSource() datasource.DataSource {
	return &currentIdentityDataSource{}
}

func (d *currentIdentityDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_current_identity"
}

func (d *currentIdentityDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	computed := func(description string) schema.StringAttribute {
		return schema.StringAttribute{MarkdownDescription: description, Computed: true}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "The tenant, region and service account the provider is authenticated as, from the public API `whoami` call the provider makes when it starts.",
		Attributes: map[string]schema.Attribute{
			"tenant_id":           computed("The Act tenant ID."),
			"tenant_display_name": computed("The tenant's display name."),
			"region":              computed("The Act region serving the tenant, such as `us1`. Null in local development stacks."),
			"principal_kind":      computed("The kind of principal, `service_account`."),
			"principal_id":        computed("The service account's client ID."),
			"principal_name":      computed("The service account's name."),
			"principal_role":      computed("The service account's role, when it has one."),
			"token_scope":         computed("The scope of the current token, `act:read` or `act:write`."),
			"scopes": schema.ListAttribute{
				MarkdownDescription: "Every scope the current token carries.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"auth_method":       computed("How the provider authenticated, such as `client_credentials`."),
			"phase":             computed("The tenant's onboarding phase, when the API reports one."),
			"token_expires_at":  computed("When the current token expires, in RFC 3339."),
			"federation_issuer": computed("The external issuer for federated workload identity, when used."),
		},
	}
}

func (d *currentIdentityDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *currentIdentityDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	if d.data == nil || d.data.Whoami == nil {
		resp.Diagnostics.AddError("Provider not configured", "The Act provider has no credentials. Set client_id and client_secret.")
		return
	}
	w := d.data.Whoami
	scopes, diags := types.ListValueFrom(ctx, types.StringType, w.Scopes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	model := currentIdentityModel{
		TenantID:          types.StringValue(w.TenantID),
		TenantDisplayName: types.StringValue(w.TenantDisplayName),
		Region:            types.StringPointerValue(w.Region),
		PrincipalKind:     types.StringValue(string(w.Principal.Kind)),
		PrincipalID:       types.StringValue(w.Principal.ID),
		PrincipalName:     types.StringValue(w.Principal.Name),
		PrincipalRole:     types.StringPointerValue(w.Principal.Role),
		TokenScope:        types.StringValue(string(w.TokenScope)),
		Scopes:            scopes,
		AuthMethod:        types.StringValue(string(w.AuthMethod)),
		Phase:             types.StringPointerValue(w.Phase),
		TokenExpiresAt:    types.StringValue(w.TokenExpiresAt.UTC().Format(time.RFC3339)),
		FederationIssuer:  types.StringNull(),
	}
	if w.Federation != nil {
		model.FederationIssuer = types.StringValue(w.Federation.Issuer)
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}
