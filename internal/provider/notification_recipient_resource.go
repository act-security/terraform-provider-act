package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

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

type notificationRecipientModel struct {
	ID       types.String       `tfsdk:"id"`
	Name     types.String       `tfsdk:"name"`
	Email    []emailActionModel `tfsdk:"email"`
	Slack    []slackActionModel `tfsdk:"slack"`
	Revision types.Int64        `tfsdk:"revision"`
	RuleIDs  types.Set          `tfsdk:"rule_ids"`
}

func NewNotificationRecipientResource() resource.Resource { return &notificationRecipientResource{} }

func (r *notificationRecipientResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_recipient"
}

func (r *notificationRecipientResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "A tenant-wide address-book entry for notification rules: a name and the email addresses and Slack channels it stands for. Rules reference it in `recipient_ids`. Notification rules are in preview; the tenant needs them enabled.",
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
			"revision": schema.Int64Attribute{
				MarkdownDescription: "The recipient's revision in Act. It goes up on every change.",
				Computed:            true,
			},
			"rule_ids": schema.SetAttribute{
				MarkdownDescription: "The notification rules that reference this recipient. Act refuses to delete a recipient while any rule does.",
				ElementType:         types.StringType,
				Computed:            true,
			},
		},
		Blocks: actionBlocks("this recipient stands for"),
	}
}

func (r *notificationRecipientResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var email, slack types.List
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("email"), &email)...)
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, path.Root("slack"), &slack)...)
	if resp.Diagnostics.HasError() || email.IsUnknown() || slack.IsUnknown() {
		return
	}
	if len(email.Elements())+len(slack.Elements()) == 0 {
		resp.Diagnostics.AddError("Missing delivery method", "A notification recipient needs an email block, a slack block, or both.")
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
	keepStateWhenOnlyComputedDiffer(ctx, req, resp, "revision", "rule_ids")
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
	return apigen.NotificationRecipientWrite{Name: m.Name.ValueString(), Methods: actionsOf(ctx, m.Email, m.Slack, diags)}
}

func recipientModelOf(ctx context.Context, recipient apigen.NotificationRecipient, prior notificationRecipientModel, diags *diag.Diagnostics) notificationRecipientModel {
	email, slack := actionModelsOf(ctx, recipient.Methods, prior.Email, diags)
	return notificationRecipientModel{
		ID:       types.StringValue(recipient.ID),
		Name:     types.StringValue(recipient.Name),
		Email:    email,
		Slack:    slack,
		Revision: types.Int64Value(int64(recipient.Revision)),
		RuleIDs:  stringSet(ctx, recipient.RuleIds, diags),
	}
}
