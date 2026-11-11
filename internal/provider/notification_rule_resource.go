package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
)

type notificationRuleResource struct {
	data *ProviderData
}

var (
	_ resource.ResourceWithConfigure   = (*notificationRuleResource)(nil)
	_ resource.ResourceWithImportState = (*notificationRuleResource)(nil)
	_ resource.ResourceWithModifyPlan  = (*notificationRuleResource)(nil)
)

type notificationConditionModel struct {
	EventType types.String `tfsdk:"event_type"`
	Field     types.String `tfsdk:"field"`
	Operator  types.String `tfsdk:"operator"`
	Values    types.Set    `tfsdk:"values"`
}

type notificationRuleModel struct {
	ID                types.String                 `tfsdk:"id"`
	Name              types.String                 `tfsdk:"name"`
	Enabled           types.Bool                   `tfsdk:"enabled"`
	EventTypes        types.Set                    `tfsdk:"event_types"`
	Conditions        []notificationConditionModel `tfsdk:"condition"`
	Email             []emailActionModel           `tfsdk:"email"`
	Slack             []slackActionModel           `tfsdk:"slack"`
	RecipientIDs      types.Set                    `tfsdk:"recipient_ids"`
	Revision          types.Int64                  `tfsdk:"revision"`
	MinClientRevision types.Int64                  `tfsdk:"min_client_revision"`
	CreatedVia        types.String                 `tfsdk:"created_via"`
	LastModifiedVia   types.String                 `tfsdk:"last_modified_via"`
	WebURL            types.String                 `tfsdk:"web_url"`
}

func NewNotificationRuleResource() resource.Resource { return &notificationRuleResource{} }

func (r *notificationRuleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_notification_rule"
}

func (r *notificationRuleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	blocks := actionBlocks("to notify")
	blocks["condition"] = schema.ListNestedBlock{
		MarkdownDescription: "Narrows one event type to the events whose `field` has one of `values`. Up to 10. The `act_notification_event_types` data source lists the fields each event type takes.",
		Validators:          []validator.List{listvalidator.SizeAtMost(10)},
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"event_type": schema.StringAttribute{
				MarkdownDescription: "The event type the condition applies to. It must be one of `event_types`.",
				Required:            true,
			},
			"field": schema.StringAttribute{
				MarkdownDescription: "The event field to match, such as `source`.",
				Required:            true,
			},
			"operator": schema.StringAttribute{
				MarkdownDescription: "How to match. Only `in` exists today, which is the default.",
				Optional:            true,
				Computed:            true,
				Default:             stringdefault.StaticString("in"),
			},
			"values": schema.SetAttribute{
				MarkdownDescription: "The values to match, up to 20, such as `policy_mgmt`.",
				ElementType:         types.StringType,
				Required:            true,
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 20)},
			},
		}},
	}
	resp.Schema = schema.Schema{
		MarkdownDescription: "A notification rule: when an event of one of `event_types` happens and passes the rule's `condition` blocks for its type, Act sends it by email, to Slack and to the address-book entries in `recipient_ids`. Notification rules are in preview; the tenant needs them enabled.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "The rule ID.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "The name Act shows for the rule, up to 100 characters.",
				Required:            true,
				Validators:          []validator.String{stringvalidator.LengthBetween(1, 100)},
			},
			"enabled": schema.BoolAttribute{
				MarkdownDescription: "Whether the rule sends notifications. Defaults to `true`.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"event_types": schema.SetAttribute{
				MarkdownDescription: "The event types that trigger the rule, up to 10, joined by OR, such as `simulation.finished`. The `act_notification_event_types` data source lists them.",
				ElementType:         types.StringType,
				Required:            true,
				Validators:          []validator.Set{setvalidator.SizeBetween(1, 10)},
			},
			"recipient_ids": schema.SetAttribute{
				MarkdownDescription: "IDs of `act_notification_recipient` entries to notify as well, up to 20.",
				ElementType:         types.StringType,
				Optional:            true,
				Validators: []validator.Set{
					setvalidator.SizeAtMost(20),
					setvalidator.ValueStringsAre(stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")),
				},
			},
			"revision": schema.Int64Attribute{
				MarkdownDescription: "The rule's revision in Act. It goes up on every change, from Terraform or the Act console.",
				Computed:            true,
			},
			"min_client_revision": schema.Int64Attribute{
				MarkdownDescription: fmt.Sprintf("The oldest client revision that understands every part of the rule. This provider understands revision %d and warns when a rule needs a newer one: Act keeps the parts Terraform cannot show when it updates the rule.", supportedClientRevision),
				Computed:            true,
			},
			"created_via": schema.StringAttribute{
				MarkdownDescription: "Where the rule was created: `api` or `ui`.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"last_modified_via": schema.StringAttribute{
				MarkdownDescription: "Where the rule last changed: `api` or `ui`.",
				Computed:            true,
			},
			"web_url": schema.StringAttribute{
				MarkdownDescription: "The rule's page in the Act console, when Act reports one.",
				Computed:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
		Blocks: blocks,
	}
}

func (r *notificationRuleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func ruleWriteOf(ctx context.Context, m notificationRuleModel, diags *diag.Diagnostics) apigen.NotificationRuleWrite {
	enabled := m.Enabled.ValueBool()
	conditions := []apigen.NotificationCondition{}
	for _, condition := range m.Conditions {
		conditions = append(conditions, apigen.NotificationCondition{
			EventType: condition.EventType.ValueString(),
			Field:     apigen.NotificationConditionField(condition.Field.ValueString()),
			Operator:  apigen.NotificationConditionOperator(condition.Operator.ValueString()),
			Values:    stringsOf(ctx, condition.Values, diags),
		})
	}
	actions := actionsOf(ctx, m.Email, m.Slack, diags)
	recipientIDs := stringsOf(ctx, m.RecipientIDs, diags)
	return apigen.NotificationRuleWrite{
		Name:         m.Name.ValueString(),
		Enabled:      &enabled,
		EventTypes:   stringsOf(ctx, m.EventTypes, diags),
		Conditions:   &conditions,
		Actions:      &actions,
		RecipientIds: &recipientIDs,
	}
}

func ruleModelOf(ctx context.Context, rule apigen.NotificationRule, prior notificationRuleModel, diags *diag.Diagnostics) notificationRuleModel {
	conditions := []notificationConditionModel{}
	for _, condition := range rule.Conditions {
		conditions = append(conditions, notificationConditionModel{
			EventType: types.StringValue(condition.EventType),
			Field:     types.StringValue(string(condition.Field)),
			Operator:  types.StringValue(string(condition.Operator)),
			Values:    stringSet(ctx, condition.Values, diags),
		})
	}
	email, slack := actionModelsOf(ctx, rule.Actions, prior.Email, diags)
	return notificationRuleModel{
		ID:                types.StringValue(rule.ID),
		Name:              types.StringValue(rule.Name),
		Enabled:           types.BoolValue(rule.Enabled),
		EventTypes:        stringSet(ctx, rule.EventTypes, diags),
		Conditions:        conditions,
		Email:             email,
		Slack:             slack,
		RecipientIDs:      optionalStringSet(ctx, rule.RecipientIds, prior.RecipientIDs, diags),
		Revision:          types.Int64Value(int64(rule.Revision)),
		MinClientRevision: types.Int64Value(int64(rule.MinClientRevision)),
		CreatedVia:        types.StringValue(string(rule.CreatedVia)),
		LastModifiedVia:   types.StringValue(string(rule.LastModifiedVia)),
		WebURL:            types.StringPointerValue(rule.WebURL),
	}
}

func warnNewerRule(diags *diag.Diagnostics, rule apigen.NotificationRule) {
	if rule.MinClientRevision <= supportedClientRevision {
		return
	}
	diags.AddWarning(
		"Notification rule uses features this provider does not know",
		fmt.Sprintf("Rule %s (%q) needs client revision %d, and this provider understands revision %d. Terraform cannot show those parts of the rule; Act keeps them when Terraform updates it. Upgrade the provider to manage them.", rule.ID, rule.Name, rule.MinClientRevision, supportedClientRevision),
	)
}

func (r *notificationRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	keepStateWhenOnlyComputedDiffer(ctx, req, resp, "revision", "min_client_revision", "last_modified_via")
}

func (r *notificationRuleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan notificationRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := ruleWriteOf(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.data.Client.CreateNotificationRule(ctx, body, idempotencyKey())
	if err != nil {
		addNotificationWriteError(&resp.Diagnostics, "Could not create the notification rule", "notification rule", "actions", body, err)
		return
	}
	warnNewerRule(&resp.Diagnostics, result.Rule)
	state := ruleModelOf(ctx, result.Rule, plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRuleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var prior notificationRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.data.Client.GetNotificationRule(ctx, prior.ID.ValueString())
	if err != nil {
		notificationReadError(&resp.Diagnostics, "Reading the notification rule failed", err)
		return
	}
	if result == nil {
		resp.State.RemoveResource(ctx)
		return
	}
	warnNewerRule(&resp.Diagnostics, result.Rule)
	state := ruleModelOf(ctx, result.Rule, prior, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRuleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, prior notificationRuleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body := ruleWriteOf(ctx, plan, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	etag := revisionETag(privateString(ctx, req.Private, privateETag), prior.Revision)
	result, err := r.data.Client.ReplaceNotificationRule(ctx, prior.ID.ValueString(), etag, body)
	if err != nil {
		addNotificationWriteError(&resp.Diagnostics, "Could not update the notification rule", "notification rule", "actions", body, err)
		return
	}
	warnNewerRule(&resp.Diagnostics, result.Rule)
	state := ruleModelOf(ctx, result.Rule, plan, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
	setPrivate(ctx, resp.Private, privateETag, result.ETag, &resp.Diagnostics)
}

func (r *notificationRuleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var prior notificationRuleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	etag := revisionETag(privateString(ctx, req.Private, privateETag), prior.Revision)
	if err := r.data.Client.DeleteNotificationRule(ctx, prior.ID.ValueString(), etag); err != nil {
		addNotificationWriteError(&resp.Diagnostics, "Could not delete the notification rule", "notification rule", "actions", nil, err)
	}
}

func (r *notificationRuleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	id := strings.TrimSpace(req.ID)
	if !uuidPattern.MatchString(id) {
		resp.Diagnostics.AddError("Invalid import ID", "Use the notification rule ID, a lowercase UUID.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}
