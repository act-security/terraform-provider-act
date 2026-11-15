package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

type providerDataSource struct {
	data *ProviderData
}

func (d *providerDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type userDataSource struct{ providerDataSource }

var _ datasource.DataSourceWithConfigure = (*userDataSource)(nil)

type userModel struct {
	Email types.String `tfsdk:"email"`
	ID    types.String `tfsdk:"id"`
	Name  types.String `tfsdk:"name"`
}

func NewUserDataSource() datasource.DataSource { return &userDataSource{} }

func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "An Act user of this tenant, found by their exact email address. Its `id` goes in the `user_ids` of a notification recipient.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				MarkdownDescription: "The user's email address. Matched exactly, ignoring case.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, maxEmailLength)},
			},
			"id":   schema.StringAttribute{MarkdownDescription: "The user ID.", Computed: true},
			"name": schema.StringAttribute{MarkdownDescription: "The user's name, when Act knows it.", Computed: true},
		},
	}
}

func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model userModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	user, err := d.data.Client.FindUserByEmail(ctx, model.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Looking up the Act user failed", err.Error())
		return
	}
	if user == nil {
		resp.Diagnostics.AddError("Act user not found", fmt.Sprintf("No user of this tenant has the email address %q.", model.Email.ValueString()))
		return
	}
	model.ID = types.StringValue(user.ID)
	model.Name = types.StringPointerValue(user.Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type slackChannelDataSource struct{ providerDataSource }

var _ datasource.DataSourceWithConfigure = (*slackChannelDataSource)(nil)

type slackChannelModel struct {
	Name          types.String `tfsdk:"name"`
	IntegrationID types.String `tfsdk:"integration_id"`
	ID            types.String `tfsdk:"id"`
	ChannelName   types.String `tfsdk:"channel_name"`
}

func NewSlackChannelDataSource() datasource.DataSource { return &slackChannelDataSource{} }

func (d *slackChannelDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_slack_channel"
}

func (d *slackChannelDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A Slack channel the tenant's Slack integration can post to, found by its exact name. Notification rules take channel IDs, not names.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				MarkdownDescription: "The channel name, with or without `#`, or a channel ID. Matched exactly, ignoring case.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, maxSlackChannelNameLength)},
			},
			"integration_id": schema.StringAttribute{
				MarkdownDescription: "The Slack integration to search. Needed only when the tenant has more than one.",
				Optional:            true,
				Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
			},
			"id":           schema.StringAttribute{MarkdownDescription: "The channel ID, such as `C05PLATGRD2`.", Computed: true},
			"channel_name": schema.StringAttribute{MarkdownDescription: "The channel name as Slack spells it, without `#`.", Computed: true},
		},
	}
}

func (d *slackChannelDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var model slackChannelModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &model)...)
	if resp.Diagnostics.HasError() {
		return
	}
	channels, err := d.data.Client.FindSlackChannels(ctx, model.Name.ValueString(), model.IntegrationID.ValueStringPointer())
	if err != nil {
		var apiErr *client.APIError
		if asAPIError(err, &apiErr) && apiErr.Code == "integration_not_connected" {
			resp.Diagnostics.AddError("Slack is not connected", "This tenant has no connected Slack integration to search. Install one with act_slack_integration first.")
			return
		}
		notificationReadError(&resp.Diagnostics, "Looking up the Slack channel failed", err)
		return
	}
	switch len(channels) {
	case 0:
		resp.Diagnostics.AddError("Slack channel not found", fmt.Sprintf("No channel named %q is visible to the Slack integration. Check the name, and invite the Act app to a private channel.", model.Name.ValueString()))
		return
	case 1:
	default:
		ids := make([]string, 0, len(channels))
		for _, channel := range channels {
			ids = append(ids, channel.ID)
		}
		resp.Diagnostics.AddError("Several Slack channels match", fmt.Sprintf("%q matches channels %s. Use the channel ID instead.", model.Name.ValueString(), strings.Join(ids, ", ")))
		return
	}
	model.ID = types.StringValue(channels[0].ID)
	model.ChannelName = types.StringValue(channels[0].Name)
	resp.Diagnostics.Append(resp.State.Set(ctx, &model)...)
}

type notificationEventTypesDataSource struct{ providerDataSource }

var _ datasource.DataSourceWithConfigure = (*notificationEventTypesDataSource)(nil)

var conditionFieldType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"field":    types.StringType,
	"operator": types.StringType,
	"values":   types.ListType{ElemType: types.StringType},
}}

var eventTypeType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"event_type":       types.StringType,
	"category":         types.StringType,
	"title":            types.StringType,
	"description":      types.StringType,
	"action_types":     types.ListType{ElemType: types.StringType},
	"condition_fields": types.ListType{ElemType: conditionFieldType},
}}

type notificationLimit struct {
	name  string
	value func(apigen.NotificationRuleLimits) int
}

var notificationLimits = []notificationLimit{
	{"max_name_length", func(l apigen.NotificationRuleLimits) int { return l.MaxNameLength }},
	{"max_event_types_per_rule", func(l apigen.NotificationRuleLimits) int { return l.MaxEventTypesPerRule }},
	{"max_actions_per_rule", func(l apigen.NotificationRuleLimits) int { return l.MaxActionsPerRule }},
	{"max_recipients_per_rule", func(l apigen.NotificationRuleLimits) int { return l.MaxRecipientsPerRule }},
	{"max_email_recipients", func(l apigen.NotificationRuleLimits) int { return l.MaxEmailRecipients }},
	{"max_slack_channels", func(l apigen.NotificationRuleLimits) int { return l.MaxSlackChannels }},
	{"max_enabled_rules_per_event_type", func(l apigen.NotificationRuleLimits) int { return l.MaxEnabledRulesPerEventType }},
	{"max_recipient_name_length", func(l apigen.NotificationRuleLimits) int { return l.MaxRecipientNameLength }},
	{"activity_retention_months", func(l apigen.NotificationRuleLimits) int { return l.ActivityRetentionMonths }},
}

var limitsType = func() types.ObjectType {
	attrs := map[string]attr.Type{}
	for _, limit := range notificationLimits {
		attrs[limit.name] = types.Int64Type
	}
	return types.ObjectType{AttrTypes: attrs}
}()

func NewNotificationEventTypesDataSource() datasource.DataSource {
	return &notificationEventTypesDataSource{}
}

func (d *notificationEventTypesDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_event_types"
}

func (d *notificationEventTypesDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	limits := map[string]schema.Attribute{}
	for _, limit := range notificationLimits {
		limits[limit.name] = schema.Int64Attribute{MarkdownDescription: "The `" + limit.name + "` limit.", Computed: true}
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "The event types a notification rule can use in this tenant, the conditions each takes, and the limits on rules and recipients.",
		Attributes: map[string]schema.Attribute{
			"event_types": schema.ListNestedAttribute{
				MarkdownDescription: "One entry per event type.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"event_type":   schema.StringAttribute{MarkdownDescription: "The name to use in `event_types`, such as `simulation.finished`.", Computed: true},
					"category":     schema.StringAttribute{MarkdownDescription: "The catalog category.", Computed: true},
					"title":        schema.StringAttribute{MarkdownDescription: "The title Act shows.", Computed: true},
					"description":  schema.StringAttribute{MarkdownDescription: "What the event means.", Computed: true},
					"action_types": schema.ListAttribute{MarkdownDescription: "The blocks a rule for this event can use: `email`, `slack`.", ElementType: types.StringType, Computed: true},
					"condition_fields": schema.ListNestedAttribute{
						MarkdownDescription: "The `condition` fields this event type takes.",
						Computed:            true,
						NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
							"field":    schema.StringAttribute{MarkdownDescription: "The field name.", Computed: true},
							"operator": schema.StringAttribute{MarkdownDescription: "The operator.", Computed: true},
							"values":   schema.ListAttribute{MarkdownDescription: "The values the field can take.", ElementType: types.StringType, Computed: true},
						}},
					},
				}},
			},
			"limits": schema.SingleNestedAttribute{
				MarkdownDescription: "Tenant limits on notification rules and recipients.",
				Computed:            true,
				Attributes:          limits,
			},
		},
	}
}

func (d *notificationEventTypesDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	catalog, err := d.data.Client.ListNotificationEventTypes(ctx)
	if err != nil {
		notificationReadError(&resp.Diagnostics, "Listing notification event types failed", err)
		return
	}
	diags := &resp.Diagnostics
	entries := make([]attr.Value, 0, len(catalog.Items))
	for _, item := range catalog.Items {
		fields := make([]attr.Value, 0, len(item.ConditionFields))
		for _, field := range item.ConditionFields {
			fields = append(fields, objectValue(conditionFieldType, map[string]attr.Value{
				"field":    types.StringValue(string(field.Field)),
				"operator": types.StringValue(string(field.Operator)),
				"values":   listValue(types.StringType, stringValues(field.Values), diags),
			}, diags))
		}
		actionTypes := make([]string, 0, len(item.ActionTypes))
		for _, actionType := range item.ActionTypes {
			actionTypes = append(actionTypes, string(actionType))
		}
		entries = append(entries, objectValue(eventTypeType, map[string]attr.Value{
			"event_type":       types.StringValue(item.EventType),
			"category":         types.StringValue(item.Category),
			"title":            types.StringValue(item.Title),
			"description":      types.StringValue(item.Description),
			"action_types":     listValue(types.StringType, stringValues(actionTypes), diags),
			"condition_fields": listValue(conditionFieldType, fields, diags),
		}, diags))
	}
	limitValues := map[string]attr.Value{}
	for _, limit := range notificationLimits {
		limitValues[limit.name] = types.Int64Value(int64(limit.value(catalog.Limits)))
	}
	limits := objectValue(limitsType, limitValues, diags)
	eventTypes := listValue(eventTypeType, entries, diags)
	if diags.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("event_types"), eventTypes)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("limits"), limits)...)
}

func stringValues(values []string) []attr.Value {
	out := make([]attr.Value, 0, len(values))
	for _, value := range values {
		out = append(out, types.StringValue(value))
	}
	return out
}

func listValue(elementType attr.Type, elements []attr.Value, diags *diag.Diagnostics) types.List {
	value, d := types.ListValue(elementType, elements)
	diags.Append(d...)
	return value
}

func objectValue(objectType types.ObjectType, values map[string]attr.Value, diags *diag.Diagnostics) types.Object {
	value, d := types.ObjectValue(objectType.AttrTypes, values)
	diags.Append(d...)
	return value
}
