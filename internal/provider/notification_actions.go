package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/setvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const supportedClientRevision = 1

const (
	maxNotificationNameLength = 100
	maxRuleEventTypes         = 10
	maxRuleConditions         = 10
	maxConditionValues        = 20
	maxRuleRecipientIDs       = 20
	maxEmailRecipients        = 100
	maxSlackChannels          = 50
	maxSlackChannelNameLength = 200
	maxRecipientMembers       = 100
	maxUserIDLength           = 200
	maxEmailLength            = 320
)

var (
	slackChannelIDPattern = regexp.MustCompile(`^[A-Z0-9]+$`)
	lowercaseEmailPattern = regexp.MustCompile(`^[^A-Z\s](?:[^A-Z]*[^A-Z\s])?$`)
)

const lowercaseEmailMessage = "must be lowercase, with no surrounding spaces"

type notificationKind struct {
	noun   string
	pathOf func(pointer string, body any) (path.Path, bool)
}

var (
	notificationRuleKind      = notificationKind{noun: "notification rule", pathOf: ruleAttributePath}
	notificationRecipientKind = notificationKind{noun: "notification recipient", pathOf: recipientAttributePath}
)

type notificationWriteFailure struct {
	kind notificationKind
	verb string
	body any
	err  error
}

func (f notificationWriteFailure) summary() string {
	return "Could not " + f.verb + " the " + f.kind.noun
}

type emailActionModel struct {
	IntegrationID types.String `tfsdk:"integration_id"`
	Recipients    types.Set    `tfsdk:"recipients"`
}

type slackActionModel struct {
	IntegrationID types.String `tfsdk:"integration_id"`
	ChannelIDs    types.Set    `tfsdk:"channel_ids"`
}

func actionBlocks() map[string]schema.Block {
	return map[string]schema.Block{
		"email": schema.ListNestedBlock{
			MarkdownDescription: "Send email. At most one block.",
			Validators:          []validator.List{listvalidator.SizeAtMost(1)},
			NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
				"integration_id": schema.StringAttribute{
					MarkdownDescription: "The ID of the Act-managed email integration, from the `act_integration` data source with `type = \"email\"`.",
					Required:            true,
					Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
				},
				"recipients": schema.SetAttribute{
					MarkdownDescription: fmt.Sprintf("The email addresses to notify, up to %d, in lowercase.", maxEmailRecipients),
					ElementType:         types.StringType,
					Required:            true,
					Validators: []validator.Set{
						setvalidator.SizeBetween(1, maxEmailRecipients),
						setvalidator.ValueStringsAre(stringvalidator.RegexMatches(lowercaseEmailPattern, lowercaseEmailMessage)),
					},
				},
			}},
		},
		"slack": schema.ListNestedBlock{
			MarkdownDescription: "Post to Slack. At most one block.",
			Validators:          []validator.List{listvalidator.SizeAtMost(1)},
			NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
				"integration_id": schema.StringAttribute{
					MarkdownDescription: "The ID of the Slack integration, from `act_slack_integration` or the `act_integration` data source.",
					Required:            true,
					Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
				},
				"channel_ids": schema.SetAttribute{
					MarkdownDescription: fmt.Sprintf("The Slack channel IDs to post to, up to %d, such as `C05PLATGRD2`. Act does not take channel names; look an ID up with the `act_slack_channel` data source.", maxSlackChannels),
					ElementType:         types.StringType,
					Required:            true,
					Validators: []validator.Set{
						setvalidator.SizeBetween(1, maxSlackChannels),
						setvalidator.ValueStringsAre(stringvalidator.RegexMatches(slackChannelIDPattern, "must be a Slack channel ID, not a #name")),
					},
				},
			}},
		},
	}
}

func actionsOf(ctx context.Context, email []emailActionModel, slack []slackActionModel, diags *diag.Diagnostics) []apigen.NotificationAction {
	actions := []apigen.NotificationAction{}
	for _, block := range email {
		recipients := []openapi_types.Email{}
		for _, value := range stringsOf(ctx, block.Recipients, diags) {
			recipients = append(recipients, apigenEmail(value))
		}
		actions = append(actions, apigen.NotificationAction{
			Type:  apigen.NotificationActionTypeEmail,
			Email: &apigen.NotificationEmailAction{IntegrationID: block.IntegrationID.ValueString(), Recipients: recipients},
		})
	}
	for _, block := range slack {
		actions = append(actions, apigen.NotificationAction{
			Type:  apigen.NotificationActionTypeSlack,
			Slack: &apigen.NotificationSlackAction{IntegrationID: block.IntegrationID.ValueString(), ChannelIds: stringsOf(ctx, block.ChannelIDs, diags)},
		})
	}
	return actions
}

func actionModelsOf(ctx context.Context, actions []apigen.NotificationAction, diags *diag.Diagnostics) ([]emailActionModel, []slackActionModel) {
	email, slack := []emailActionModel{}, []slackActionModel{}
	for _, action := range actions {
		switch action.Type {
		case apigen.NotificationActionTypeEmail:
			if action.Email == nil {
				continue
			}
			recipients := make([]string, 0, len(action.Email.Recipients))
			for _, value := range action.Email.Recipients {
				recipients = append(recipients, string(value))
			}
			email = append(email, emailActionModel{
				IntegrationID: types.StringValue(action.Email.IntegrationID),
				Recipients:    stringSet(ctx, recipients, diags),
			})
		case apigen.NotificationActionTypeSlack:
			if action.Slack == nil {
				continue
			}
			slack = append(slack, slackActionModel{
				IntegrationID: types.StringValue(action.Slack.IntegrationID),
				ChannelIDs:    stringSet(ctx, action.Slack.ChannelIds, diags),
			})
		}
	}
	return email, slack
}

func stringsOf(ctx context.Context, set types.Set, diags *diag.Diagnostics) []string {
	values := []string{}
	if set.IsNull() || set.IsUnknown() {
		return values
	}
	diags.Append(set.ElementsAs(ctx, &values, false)...)
	return values
}

func stringSet(ctx context.Context, values []string, diags *diag.Diagnostics) types.Set {
	set, d := types.SetValueFrom(ctx, types.StringType, values)
	diags.Append(d...)
	return set
}

func optionalStringSet(ctx context.Context, values []string, prior types.Set, diags *diag.Diagnostics) types.Set {
	if len(values) == 0 && prior.IsNull() {
		return types.SetNull(types.StringType)
	}
	return stringSet(ctx, values, diags)
}

func pointerValue(body any, pointer string) (string, bool) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", false
	}
	var current any
	if json.Unmarshal(raw, &current) != nil {
		return "", false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		switch node := current.(type) {
		case map[string]any:
			current = node[segment]
		case []any:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(node) {
				return "", false
			}
			current = node[index]
		default:
			return "", false
		}
	}
	value, ok := current.(string)
	return value, ok
}

var wireNames = map[string]string{
	"name":          "name",
	"enabled":       "enabled",
	"eventTypes":    "event_types",
	"recipientIds":  "recipient_ids",
	"eventType":     "event_type",
	"field":         "field",
	"operator":      "operator",
	"values":        "values",
	"integrationId": "integration_id",
	"recipients":    "recipients",
	"channelIds":    "channel_ids",
}

func ruleAttributePath(pointer string, body any) (path.Path, bool) {
	segments := pointerSegments(pointer)
	if len(segments) == 0 {
		return path.Empty(), false
	}
	setValue := func(p path.Path, at int) path.Path {
		if len(segments) > at {
			if value, ok := pointerValue(body, "/"+strings.Join(segments[:at+1], "/")); ok {
				return p.AtSetValue(types.StringValue(value))
			}
		}
		return p
	}
	switch segments[0] {
	case "name", "enabled":
		return path.Root(segments[0]), true
	case "eventTypes", "recipientIds":
		return setValue(path.Root(wireNames[segments[0]]), 1), true
	case "conditions":
		if len(segments) < 2 {
			return path.Root("condition"), true
		}
		index, err := strconv.Atoi(segments[1])
		if err != nil {
			return path.Root("condition"), true
		}
		p := path.Root("condition").AtListIndex(index)
		if len(segments) < 3 || wireNames[segments[2]] == "" {
			return p, true
		}
		p = p.AtName(wireNames[segments[2]])
		if segments[2] == "values" {
			p = setValue(p, 3)
		}
		return p, true
	case "actions":
		if len(segments) < 2 {
			return path.Empty(), false
		}
		kind := ""
		if len(segments) >= 3 {
			kind = segments[2]
		} else if value, ok := pointerValue(body, "/"+segments[0]+"/"+segments[1]+"/type"); ok {
			kind = value
		}
		if kind != "email" && kind != "slack" {
			return path.Empty(), false
		}
		p := path.Root(kind).AtListIndex(0)
		if len(segments) < 4 || wireNames[segments[3]] == "" {
			return p, true
		}
		p = p.AtName(wireNames[segments[3]])
		if segments[3] == "recipients" || segments[3] == "channelIds" {
			p = setValue(p, 4)
		}
		return p, true
	}
	return path.Empty(), false
}

func recipientAttributePath(pointer string, body any) (path.Path, bool) {
	segments := pointerSegments(pointer)
	if len(segments) == 0 {
		return path.Empty(), false
	}
	switch {
	case segments[0] == "name":
		return path.Root("name"), true
	case segments[0] == "members" && len(segments) >= 2:
		member := "/members/" + segments[1]
		kind, _ := pointerValue(body, member+"/type")
		switch kind {
		case string(apigen.NotificationRecipientMemberTypeUser):
			return memberSetPath("user_ids", body, member+"/user/userId"), true
		case string(apigen.NotificationRecipientMemberTypeEmail):
			return memberSetPath("emails", body, member+"/email/address"), true
		case string(apigen.NotificationRecipientMemberTypeSlackChannel):
			return path.Root("slack_channel"), true
		}
	}
	return path.Empty(), false
}

func memberSetPath(attribute string, body any, valuePointer string) path.Path {
	if value, ok := pointerValue(body, valuePointer); ok {
		return path.Root(attribute).AtSetValue(types.StringValue(value))
	}
	return path.Root(attribute)
}

func pointerSegments(pointer string) []string {
	trimmed := strings.TrimPrefix(pointer, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func addNotificationWriteError(diags *diag.Diagnostics, failure notificationWriteFailure) {
	summary, noun, body, err := failure.summary(), failure.kind.noun, failure.body, failure.err
	var apiErr *client.APIError
	if !asAPIError(err, &apiErr) {
		diags.AddError(summary, err.Error())
		return
	}
	pointer := apiErr.Detail("pointer")
	if pointer == "" && apiErr.Detail("attribute") != "" {
		pointer = "/" + strings.ReplaceAll(apiErr.Detail("attribute"), ".", "/")
	}
	at, mapped := failure.kind.pathOf(pointer, body)
	addAt := func(detail string) {
		if mapped {
			diags.AddAttributeError(at, summary, detail)
			return
		}
		diags.AddError(summary, detail)
	}
	switch {
	case apiErr.Code == "feature_disabled":
		diags.AddError(summary, "Notification rules are not enabled for this tenant. Ask Act to enable notification rules for the tenant, then apply again. ("+err.Error()+")")
	case apiErr.Code == "invalid_request":
		addAt("Act rejected the " + noun + ": " + invalidReason(apiErr, pointer, body) + ".")
	case apiErr.Code == "integration_not_connected":
		id, _ := pointerValue(body, pointer+"/integrationId")
		if id == "" {
			id, _ = pointerValue(body, pointer)
		}
		addAt(fmt.Sprintf("The integration %s is not installed or not connected in this tenant.", id))
	case apiErr.Status == http.StatusPreconditionFailed:
		diags.AddError(summary, "The "+noun+" changed in Act since Terraform last read it. Run terraform apply again to plan against the current version.")
	case apiErr.Code == "already_exists":
		diags.AddAttributeError(path.Root("name"), summary, "Another "+noun+" already has this name. Names are unique in the tenant.")
	case apiErr.Code == "limit_exceeded":
		detail := "A tenant limit was reached"
		if reason := apiErr.Detail("reason"); reason != "" {
			detail += ": " + reason
		}
		if eventType := apiErr.Detail("eventType"); eventType != "" {
			detail += " for " + eventType
		}
		diags.AddError(summary, detail+". "+err.Error())
	default:
		diags.AddError(summary, err.Error())
	}
}

func invalidReason(apiErr *client.APIError, pointer string, body any) string {
	reason := apiErr.Detail("reason")
	if reason == "" {
		if issues, ok := apiErr.Details["issues"].([]any); ok && len(issues) > 0 {
			if issue, ok := issues[0].(map[string]any); ok {
				if message, ok := issue["message"].(string); ok {
					reason = message
				}
			}
		}
	}
	if reason == "" {
		reason = apiErr.Message
	}
	if value, ok := pointerValue(body, pointer); ok {
		return reason + fmt.Sprintf(" (%q)", value)
	}
	if eventType := apiErr.Detail("eventType"); eventType != "" {
		reason += fmt.Sprintf(" (%q)", eventType)
	}
	return reason
}

func notificationReadError(diags *diag.Diagnostics, summary string, err error) {
	var apiErr *client.APIError
	if asAPIError(err, &apiErr) && apiErr.Code == "feature_disabled" {
		diags.AddError(summary, "Notification rules are not enabled for this tenant. Ask Act to enable notification rules for the tenant. ("+err.Error()+")")
		return
	}
	diags.AddError(summary, err.Error())
}

func revisionETag(etag string, revision types.Int64) string {
	if etag != "" {
		return etag
	}
	if revision.IsNull() || revision.IsUnknown() {
		return "*"
	}
	return strconv.Quote(strconv.FormatInt(revision.ValueInt64(), 10))
}

func keepStateWhenOnlyComputedDiffer(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse, computed ...string) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}
	var planned, stored types.Object
	resp.Diagnostics.Append(req.Plan.Get(ctx, &planned)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &stored)...)
	if resp.Diagnostics.HasError() {
		return
	}
	attributes := maps.Clone(planned.Attributes())
	for _, name := range computed {
		attributes[name] = stored.Attributes()[name]
	}
	candidate, diags := types.ObjectValue(planned.AttributeTypes(ctx), attributes)
	if diags.HasError() || !candidate.Equal(stored) {
		return
	}
	resp.Diagnostics.Append(resp.Plan.Set(ctx, stored)...)
}
