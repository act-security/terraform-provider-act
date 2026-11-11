package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework-validators/datasourcevalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

var integrationTypeNames = []string{"slack", "jira", "wiz", "splunk", "email"}

type integrationDataSource struct {
	data *ProviderData
}

var (
	_ datasource.DataSourceWithConfigure        = (*integrationDataSource)(nil)
	_ datasource.DataSourceWithConfigValidators = (*integrationDataSource)(nil)
)

type integrationDataSourceModel struct {
	ID           types.String `tfsdk:"id"`
	Type         types.String `tfsdk:"type"`
	DisplayName  types.String `tfsdk:"display_name"`
	Status       types.String `tfsdk:"status"`
	HealthReason types.String `tfsdk:"health_reason"`
	HealthNote   types.String `tfsdk:"health_note"`
	Config       types.Map    `tfsdk:"config"`
}

func NewIntegrationDataSource() datasource.DataSource { return &integrationDataSource{} }

func (d *integrationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration"
}

func (d *integrationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An integration installed in the tenant, found by type or by ID. Use it to reference an integration Terraform does not manage, such as the Act-owned `email` integration or one installed in the Act console. Secrets are never returned.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The integration ID. Set this or `type`.",
				Optional:            true,
				Computed:            true,
			},
			"type": schema.StringAttribute{
				MarkdownDescription: "The integration type: `slack`, `jira`, `wiz`, `splunk` or `email`. A tenant has at most one integration per type. Set this or `id`.",
				Optional:            true,
				Computed:            true,
				Validators:          []validator.String{stringvalidator.OneOf(integrationTypeNames...)},
			},
			"display_name": schema.StringAttribute{MarkdownDescription: "The name Act shows for the integration.", Computed: true},
			"status":       schema.StringAttribute{MarkdownDescription: "The connection status: `connected`, `pending`, `error` or `disconnected`.", Computed: true},
			"health_reason": schema.StringAttribute{
				MarkdownDescription: "Why the connection is unhealthy, when Act reports a reason.",
				Computed:            true,
			},
			"health_note": schema.StringAttribute{MarkdownDescription: "What to do about an unhealthy connection.", Computed: true},
			"config": schema.MapAttribute{
				MarkdownDescription: "The integration's settings that are not secret, keyed by their API names, such as `baseUrl`.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
	}
}

func (d *integrationDataSource) ConfigValidators(context.Context) []datasource.ConfigValidator {
	return []datasource.ConfigValidator{datasourcevalidator.ExactlyOneOf(path.MatchRoot("id"), path.MatchRoot("type"))}
}

func (d *integrationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *integrationDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model integrationDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var item apigen.Integration
	if !model.ID.IsNull() {
		result, err := d.data.Client.GetIntegration(ctx, model.ID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Reading the integration failed", err.Error())
			return
		}
		if result == nil {
			resp.Diagnostics.AddError("Integration not found", fmt.Sprintf("No integration %s in this tenant.", model.ID.ValueString()))
			return
		}
		item = result.Integration
	} else {
		kind := apigen.IntegrationType(model.Type.ValueString())
		items, err := d.data.Client.ListIntegrations(ctx, &kind)
		if err != nil {
			resp.Diagnostics.AddError("Listing integrations failed", err.Error())
			return
		}
		if len(items) == 0 {
			resp.Diagnostics.AddError("Integration not found", fmt.Sprintf("This tenant has no %s integration installed.", kind))
			return
		}
		item = items[0]
	}
	config, diags := types.MapValueFrom(ctx, types.StringType, item.Config)
	resp.Diagnostics.Append(diags...)
	model.ID = types.StringValue(item.ID)
	model.Type = types.StringValue(string(item.Type))
	model.DisplayName = types.StringValue(item.DisplayName)
	model.Status = types.StringValue(string(item.Status))
	model.HealthReason, model.HealthNote = types.StringNull(), types.StringNull()
	if item.Health != nil {
		model.HealthReason = types.StringPointerValue(item.Health.Reason)
		model.HealthNote = types.StringPointerValue(item.Health.Note)
	}
	model.Config = config
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type integrationTypesDataSource struct {
	data *ProviderData
}

var _ datasource.DataSourceWithConfigure = (*integrationTypesDataSource)(nil)

var integrationFieldType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"name":      types.StringType,
	"sensitive": types.BoolType,
}}

var integrationTypeType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"type":         types.StringType,
	"display_name": types.StringType,
	"category":     types.StringType,
	"installable":  types.BoolType,
	"installed":    types.BoolType,
	"fields":       types.ListType{ElemType: integrationFieldType},
}}

func NewIntegrationTypesDataSource() datasource.DataSource { return &integrationTypesDataSource{} }

func (d *integrationTypesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_integration_types"
}

func (d *integrationTypesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The integration types this tenant can use, whether each is installed, and which of its fields are secret.",
		Attributes: map[string]schema.Attribute{
			"types": schema.ListNestedAttribute{
				MarkdownDescription: "One entry per integration type.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"type":         schema.StringAttribute{MarkdownDescription: "The type, such as `slack`.", Computed: true},
					"display_name": schema.StringAttribute{MarkdownDescription: "The name Act shows.", Computed: true},
					"category":     schema.StringAttribute{MarkdownDescription: "The catalog category, such as `notifications`.", Computed: true},
					"installable": schema.BoolAttribute{
						MarkdownDescription: "Whether Terraform can install it. Act-owned types such as `email` are installed for every tenant.",
						Computed:            true,
					},
					"installed": schema.BoolAttribute{MarkdownDescription: "Whether the tenant has it installed.", Computed: true},
					"fields": schema.ListNestedAttribute{
						MarkdownDescription: "The type's fields, by API name.",
						Computed:            true,
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"name":      schema.StringAttribute{MarkdownDescription: "The field's API name.", Computed: true},
							"sensitive": schema.BoolAttribute{MarkdownDescription: "Whether the field is a secret, which Act never returns.", Computed: true},
						}},
					},
				}},
			},
		},
	}
}

func (d *integrationTypesDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *integrationTypesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	items, err := d.data.Client.ListIntegrationTypes(ctx)
	if err != nil {
		resp.Diagnostics.AddError("Listing integration types failed", err.Error())
		return
	}
	entries := make([]attr.Value, 0, len(items))
	for _, item := range items {
		fields := make([]attr.Value, 0, len(item.Fields))
		for _, field := range item.Fields {
			value, diags := types.ObjectValue(integrationFieldType.AttrTypes, map[string]attr.Value{
				"name":      types.StringValue(field.Name),
				"sensitive": types.BoolValue(field.Sensitive),
			})
			resp.Diagnostics.Append(diags...)
			fields = append(fields, value)
		}
		fieldList, diags := types.ListValue(integrationFieldType, fields)
		resp.Diagnostics.Append(diags...)
		entry, diags := types.ObjectValue(integrationTypeType.AttrTypes, map[string]attr.Value{
			"type":         types.StringValue(string(item.Type)),
			"display_name": types.StringValue(item.DisplayName),
			"category":     types.StringValue(item.Category),
			"installable":  types.BoolValue(item.Installable),
			"installed":    types.BoolValue(item.Installed),
			"fields":       fieldList,
		})
		resp.Diagnostics.Append(diags...)
		entries = append(entries, entry)
	}
	list, diags := types.ListValue(integrationTypeType, entries)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("types"), list)...)
}
