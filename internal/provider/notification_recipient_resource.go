package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

type notificationRecipientResource struct {
	data *ProviderData
}

var (
	_ resource.ResourceWithConfigure      = (*notificationRecipientResource)(nil)
	_ resource.ResourceWithImportState    = (*notificationRecipientResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*notificationRecipientResource)(nil)
	_ resource.ResourceWithValidateConfig = (*notificationRecipientResource)(nil)
)

type slackChannelMemberModel struct {
	IntegrationID types.String `tfsdk:"integration_id"`
	ChannelID     types.String `tfsdk:"channel_id"`
}

type notificationRecipientModel struct {
	ID                types.String              `tfsdk:"id"`
	Name              types.String              `tfsdk:"name"`
	UserIDs           types.Set                 `tfsdk:"user_ids"`
	Emails            types.Set                 `tfsdk:"emails"`
	SlackChannels     []slackChannelMemberModel `tfsdk:"slack_channel"`
	Members           types.List                `tfsdk:"members"`
	Revision          types.Int64               `tfsdk:"revision"`
	MinClientRevision types.Int64               `tfsdk:"min_client_revision"`
	RuleIDs           types.Set                 `tfsdk:"rule_ids"`
	CreatedVia        types.String              `tfsdk:"created_via"`
	LastModifiedVia   types.String              `tfsdk:"last_modified_via"`
}

var recipientMemberType = types.ObjectType{AttrTypes: map[string]attr.Type{
	"type":           types.StringType,
	"user_id":        types.StringType,
	"user_name":      types.StringType,
	"user_email":     types.StringType,
	"in_tenant":      types.BoolType,
	"address":        types.StringType,
	"integration_id": types.StringType,
	"channel_id":     types.StringType,
	"channel_name":   types.StringType,
}}

func NewNotificationRecipientResource() resource.Resource { return &notificationRecipientResource{} }

func (r *notificationRecipientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_recipient"
}

func (r *notificationRecipientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: fmt.Sprintf("A tenant-wide recipient group for notification rules: a name and up to %d members, which are Act users, email addresses and Slack channels. Rules reference it in `recipient_ids`. Notification rules are in preview; the tenant needs them enabled.", maxRecipientMembers),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The recipient ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: fmt.Sprintf("The name Act shows, up to %d characters. Unique in the tenant.", maxNotificationNameLength),
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, maxNotificationNameLength)},
			},
			"user_ids": schema.SetAttribute{
				MarkdownDescription: "Act users of this tenant, from the `act_user` data source. Each user gets alerts through the receiver they chose in their Act profile (email or Slack), which Terraform does not manage.",
				ElementType:         types.StringType,
				Optional:            true,
				Validators: []validator.Set{
					setvalidator.SizeAtMost(maxRecipientMembers),
					setvalidator.ValueStringsAre(stringvalidator.LengthBetween(1, maxUserIDLength)),
				},
			},
			"emails": schema.SetAttribute{
				MarkdownDescription: "Email addresses, in lowercase.",
				ElementType:         types.StringType,
				Optional:            true,
				Validators: []validator.Set{
					setvalidator.SizeAtMost(maxRecipientMembers),
					setvalidator.ValueStringsAre(
						stringvalidator.LengthAtMost(maxEmailLength),
						stringvalidator.RegexMatches(lowercaseEmailPattern, lowercaseEmailMessage),
					),
				},
			},
			"members": schema.ListNestedAttribute{
				MarkdownDescription: "Every member as Act reports it, with the user names and channel names Act resolved. `in_tenant` is false for a user who has left the tenant; such a member receives nothing.",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
					"type":           schema.StringAttribute{MarkdownDescription: "`user`, `email` or `slack_channel`.", Computed: true},
					"user_id":        schema.StringAttribute{MarkdownDescription: "The user ID, for a `user` member.", Computed: true},
					"user_name":      schema.StringAttribute{MarkdownDescription: "The user's name, when Act knows it.", Computed: true},
					"user_email":     schema.StringAttribute{MarkdownDescription: "The user's email address, when Act knows it.", Computed: true},
					"in_tenant":      schema.BoolAttribute{MarkdownDescription: "Whether the user is still in the tenant.", Computed: true},
					"address":        schema.StringAttribute{MarkdownDescription: "The address, for an `email` member.", Computed: true},
					"integration_id": schema.StringAttribute{MarkdownDescription: "The Slack integration, for a `slack_channel` member.", Computed: true},
					"channel_id":     schema.StringAttribute{MarkdownDescription: "The Slack channel ID, for a `slack_channel` member.", Computed: true},
					"channel_name":   schema.StringAttribute{MarkdownDescription: "The channel name, when Slack reported one.", Computed: true},
				}},
			},
			"revision": schema.Int64Attribute{
				MarkdownDescription: "The recipient's revision in Act. It goes up on every change.",
				Computed:            true,
			},
			"min_client_revision": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("The oldest client revision that can show every member. This provider understands revision %d and refuses to update a recipient that needs a newer one, so it never drops members it cannot see.", supportedClientRevision),
				Computed:            true,
			},
			"rule_ids": schema.SetAttribute{
				MarkdownDescription: "The notification rules that reference this recipient. Act refuses to delete a recipient while any rule does.",
				ElementType:         types.StringType,
				Computed:            true,
			},
			"created_via": schema.StringAttribute{
				MarkdownDescription: "Where the recipient was created: `terraform`, `api` or `ui`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_modified_via": schema.StringAttribute{
				MarkdownDescription: "Where the recipient last changed: `terraform`, `api` or `ui`.",
				Computed:            true,
			},
		},
		Blocks: map[string]schema.Block{
			"slack_channel": schema.SetNestedBlock{
				MarkdownDescription: "A Slack channel. Repeat the block for more channels; they may come from different Slack integrations.",
				Validators:          []validator.Set{setvalidator.SizeAtMost(maxRecipientMembers)},
				NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
					"integration_id": schema.StringAttribute{
						MarkdownDescription: "The Slack integration, from `act_slack_integration` or the `act_integration` data source.",
						Required:            true,
						Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
					},
					"channel_id": schema.StringAttribute{
						MarkdownDescription: "The Slack channel ID, such as `C05PLATGRD2`, from the `act_slack_channel` data source.",
						Required:            true,
						Validators:          []validator.String{stringvalidator.RegexMatches(slackChannelIDPattern, "must be a Slack channel ID, not a #name")},
					},
				}},
			},
		},
	}
}

func (r *notificationRecipientResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var userIDs, emails, slackChannels types.Set
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("user_ids"), &userIDs)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("emails"), &emails)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("slack_channel"), &slackChannels)...)
	if resp.Diagnostics.HasError() || userIDs.IsUnknown() || emails.IsUnknown() || slackChannels.IsUnknown() {
		return
	}
	count := len(userIDs.Elements()) + len(emails.Elements()) + len(slackChannels.Elements())
	switch {
	case count == 0:
		resp.Diagnostics.AddError("Missing members", "A notification recipient needs at least one of user_ids, emails or a slack_channel block.")
	case count > maxRecipientMembers:
		resp.Diagnostics.AddError("Too many members", fmt.Sprintf("A notification recipient has at most %d members across user_ids, emails and slack_channel blocks; this one has %d.", maxRecipientMembers, count))
	}
}

func (r *notificationRecipientResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *notificationRecipientResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	keepStateWhenOnlyComputedDiffer(ctx, req, resp, "revision", "min_client_revision", "rule_ids", "members", "last_modified_via")
	requireWriteScope(plannedWrite{data: r.data, scope: integrationsWriteScope, req: req, resp: resp})
}

func (r *notificationRecipientResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan notificationRecipientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := recipientWriteOf(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.data.Client.CreateNotificationRecipient(ctx, body, idempotencyKey())
	if err != nil {
		addNotificationWriteError(&resp.Diagnostics, notificationWriteFailure{kind: notificationRecipientKind, verb: "create", body: body, err: err})
		return
	}
	warnAboutRecipient(&resp.Diagnostics, result.Value)
	state := recipientModelOf(ctx, result.Value, plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRecipientResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var prior notificationRecipientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.data.Client.GetNotificationRecipient(ctx, prior.ID.ValueString())
	if err != nil {
		notificationReadError(&resp.Diagnostics, "Reading the notification recipient failed", err)
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	warnAboutRecipient(&resp.Diagnostics, result.Value)
	state := recipientModelOf(ctx, result.Value, prior, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRecipientResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior notificationRecipientModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if needs := prior.MinClientRevision.ValueInt64(); needs > supportedClientRevision {
		resp.Diagnostics.AddError("Could not update the notification recipient", fmt.Sprintf("Recipient %s has members that need client revision %d, and this provider understands revision %d. An update would drop those members, so the provider does not send one. Upgrade the provider, or edit the recipient in the Act console.", prior.ID.ValueString(), needs, supportedClientRevision))
		return
	}
	body := recipientWriteOf(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	etag := revisionETag(privateString(ctx, req.Private, privateETag), prior.Revision)
	result, err := r.data.Client.ReplaceNotificationRecipient(ctx, prior.ID.ValueString(), etag, body)
	if err != nil {
		addNotificationWriteError(&resp.Diagnostics, notificationWriteFailure{kind: notificationRecipientKind, verb: "update", body: body, err: err})
		return
	}
	warnAboutRecipient(&resp.Diagnostics, result.Value)
	state := recipientModelOf(ctx, result.Value, plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRecipientResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var prior notificationRecipientModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	etag := revisionETag(privateString(ctx, req.Private, privateETag), prior.Revision)
	err := r.data.Client.DeleteNotificationRecipient(ctx, prior.ID.ValueString(), etag)
	if err == nil {
		return
	}
	failure := notificationWriteFailure{kind: notificationRecipientKind, verb: "delete", err: err}
	var apiErr *client.APIError
	if asAPIError(err, &apiErr) && apiErr.Code == "conflict" && apiErr.Detail("reason") == "notification_recipient_in_use" {
		resp.Diagnostics.AddError(
			failure.summary(),
			fmt.Sprintf("Recipient %s is still named by notification rules %s. Remove it from their recipient_ids first; when Terraform manages those rules, reference this resource's id there so Terraform orders the change.", prior.ID.ValueString(), strings.Join(apiErr.DetailStrings("ruleIds"), ", ")),
		)
		return
	}
	addNotificationWriteError(&resp.Diagnostics, failure)
}

func (r *notificationRecipientResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if !uuidPattern.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID", "Use the notification recipient ID, a lowercase UUID.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func recipientWriteOf(ctx context.Context, m notificationRecipientModel, diags *diag.Diagnostics) apigen.NotificationRecipientWrite {
	members := []apigen.NotificationRecipientMemberWrite{}
	for _, address := range stringsOf(ctx, m.Emails, diags) {
		members = append(members, apigen.NotificationRecipientMemberWrite{
			Type:  apigen.NotificationRecipientMemberTypeEmail,
			Email: &apigen.NotificationRecipientEmailMember{Address: openapi_types.Email(address)},
		})
	}
	for _, channel := range m.SlackChannels {
		members = append(members, apigen.NotificationRecipientMemberWrite{
			Type: apigen.NotificationRecipientMemberTypeSlackChannel,
			SlackChannel: &apigen.NotificationRecipientSlackChannelMemberWrite{
				IntegrationID: channel.IntegrationID.ValueString(),
				ChannelID:     channel.ChannelID.ValueString(),
			},
		})
	}
	for _, userID := range stringsOf(ctx, m.UserIDs, diags) {
		members = append(members, apigen.NotificationRecipientMemberWrite{
			Type: apigen.NotificationRecipientMemberTypeUser,
			User: &apigen.NotificationRecipientUserMemberWrite{UserID: userID},
		})
	}
	return apigen.NotificationRecipientWrite{Name: m.Name.ValueString(), Members: members}
}

func warnAboutRecipient(diags *diag.Diagnostics, recipient apigen.NotificationRecipient) {
	if recipient.MinClientRevision > supportedClientRevision {
		diags.AddWarning(
			"Notification recipient has members this provider does not know",
			fmt.Sprintf("Recipient %s (%q) needs client revision %d, and this provider understands revision %d. Terraform cannot show those members and will not update the recipient. Upgrade the provider to manage it.", recipient.ID, recipient.Name, recipient.MinClientRevision, supportedClientRevision),
		)
	}
	if departed := departedUserIDs(recipient.Members); len(departed) > 0 {
		diags.AddWarning(
			"Notification recipient names users who left the tenant",
			fmt.Sprintf("Recipient %s (%q) names users %s, who are no longer in the tenant and receive nothing. Remove them from user_ids.", recipient.ID, recipient.Name, strings.Join(departed, ", ")),
		)
	}
}

func departedUserIDs(members []apigen.NotificationRecipientMember) []string {
	departed := []string{}
	for _, member := range members {
		if member.User != nil && !member.User.InTenant {
			departed = append(departed, member.User.UserID)
		}
	}
	return departed
}

func recipientModelOf(ctx context.Context, recipient apigen.NotificationRecipient, prior notificationRecipientModel, diags *diag.Diagnostics) notificationRecipientModel {
	userIDs, emails := []string{}, []string{}
	slackChannels := []slackChannelMemberModel{}
	for _, member := range recipient.Members {
		switch member.Type {
		case apigen.NotificationRecipientMemberTypeUser:
			if member.User != nil {
				userIDs = append(userIDs, member.User.UserID)
			}
		case apigen.NotificationRecipientMemberTypeEmail:
			if member.Email != nil {
				emails = append(emails, string(member.Email.Address))
			}
		case apigen.NotificationRecipientMemberTypeSlackChannel:
			if member.SlackChannel != nil {
				slackChannels = append(slackChannels, slackChannelMemberModel{
					IntegrationID: types.StringValue(member.SlackChannel.IntegrationID),
					ChannelID:     types.StringValue(member.SlackChannel.ChannelID),
				})
			}
		}
	}
	return notificationRecipientModel{
		ID:                types.StringValue(recipient.ID),
		Name:              types.StringValue(recipient.Name),
		UserIDs:           optionalStringSet(ctx, userIDs, prior.UserIDs, diags),
		Emails:            optionalStringSet(ctx, emails, prior.Emails, diags),
		SlackChannels:     slackChannels,
		Members:           recipientMembersValue(recipient.Members, diags),
		Revision:          types.Int64Value(int64(recipient.Revision)),
		MinClientRevision: types.Int64Value(int64(recipient.MinClientRevision)),
		RuleIDs:           stringSet(ctx, recipient.RuleIds, diags),
		CreatedVia:        types.StringValue(string(recipient.CreatedVia)),
		LastModifiedVia:   types.StringValue(string(recipient.LastModifiedVia)),
	}
}

func recipientMembersValue(members []apigen.NotificationRecipientMember, diags *diag.Diagnostics) types.List {
	values := make([]attr.Value, 0, len(members))
	for _, member := range members {
		fields := map[string]attr.Value{
			"type":           types.StringValue(string(member.Type)),
			"user_id":        types.StringNull(),
			"user_name":      types.StringNull(),
			"user_email":     types.StringNull(),
			"in_tenant":      types.BoolNull(),
			"address":        types.StringNull(),
			"integration_id": types.StringNull(),
			"channel_id":     types.StringNull(),
			"channel_name":   types.StringNull(),
		}
		if user := member.User; user != nil {
			fields["user_id"] = types.StringValue(user.UserID)
			fields["user_name"] = types.StringPointerValue(user.Name)
			fields["user_email"] = types.StringPointerValue(user.Email)
			fields["in_tenant"] = types.BoolValue(user.InTenant)
		}
		if email := member.Email; email != nil {
			fields["address"] = types.StringValue(string(email.Address))
		}
		if channel := member.SlackChannel; channel != nil {
			fields["integration_id"] = types.StringValue(channel.IntegrationID)
			fields["channel_id"] = types.StringValue(channel.ChannelID)
			fields["channel_name"] = types.StringPointerValue(channel.ChannelName)
		}
		values = append(values, objectValue(recipientMemberType, fields, diags))
	}
	return listValue(recipientMemberType, values, diags)
}
