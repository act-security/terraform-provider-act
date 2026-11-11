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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

const supportedClientRevision = 1

var slackChannelIDPattern = regexp.MustCompile(`^[A-Z0-9]+$`)

type emailActionModel struct {
	IntegrationID types.String `tfsdk:"integration_id"`
	Recipients    types.Set    `tfsdk:"recipients"`
}

type slackActionModel struct {
	IntegrationID types.String `tfsdk:"integration_id"`
	ChannelIDs    types.Set    `tfsdk:"channel_ids"`
}

func actionBlocks(owner string) map[string]schema.Block {
	return map[string]schema.Block{
		"email": schema.ListNestedBlock{
			MarkdownDescription: "Send email. At most one block. Act stores addresses in lowercase; a plan never shows a change for a difference in case or order.",
			Validators:          []validator.List{listvalidator.SizeAtMost(1)},
			NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
				"integration_id": schema.StringAttribute{
					MarkdownDescription: "The ID of the Act-managed email integration, from the `act_email_integration` data source.",
					Required:            true,
					Validators:          []validator.String{stringvalidator.RegexMatches(uuidPattern, "must be a lowercase UUID")},
				},
				"recipients": schema.SetAttribute{
					MarkdownDescription: "The email addresses " + owner + ", up to 100.",
					ElementType:         types.StringType,
					Required:            true,
					Validators:          []validator.Set{setvalidator.SizeBetween(1, 100)},
					PlanModifiers:       []planmodifier.Set{caseInsensitiveSet{}},
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
					MarkdownDescription: "The Slack channel IDs " + owner + ", up to 50, such as `C05PLATGRD2`. Act does not take channel names; look an ID up with the `act_slack_channel` data source.",
					ElementType:         types.StringType,
					Required:            true,
					Validators: []validator.Set{
						setvalidator.SizeBetween(1, 50),
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

func actionModelsOf(ctx context.Context, actions []apigen.NotificationAction, priorEmail []emailActionModel, diags *diag.Diagnostics) ([]emailActionModel, []slackActionModel) {
	email, slack := []emailActionModel{}, []slackActionModel{}
	for _, action := range actions {
		switch {
		case action.Type == apigen.NotificationActionTypeEmail && action.Email != nil:
			got := make([]string, 0, len(action.Email.Recipients))
			for _, value := range action.Email.Recipients {
				got = append(got, string(value))
			}
			var prior []string
			if len(priorEmail) > 0 {
				prior = stringsOf(ctx, priorEmail[0].Recipients, diags)
			}
			email = append(email, emailActionModel{
				IntegrationID: types.StringValue(action.Email.IntegrationID),
				Recipients:    stringSet(ctx, keepSpelling(prior, got), diags),
			})
		case action.Type == apigen.NotificationActionTypeSlack && action.Slack != nil:
			slack = append(slack, slackActionModel{
				IntegrationID: types.StringValue(action.Slack.IntegrationID),
				ChannelIDs:    stringSet(ctx, action.Slack.ChannelIds, diags),
			})
		}
	}
	return email, slack
}

func keepSpelling(prior, got []string) []string {
	spelled := map[string]string{}
	for _, value := range prior {
		spelled[strings.ToLower(strings.TrimSpace(value))] = value
	}
	out := make([]string, 0, len(got))
	for _, value := range got {
		if original, ok := spelled[strings.ToLower(value)]; ok {
			out = append(out, original)
			continue
		}
		out = append(out, value)
	}
	return out
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

type caseInsensitiveSet struct{}

func (caseInsensitiveSet) Description(context.Context) string {
	return "Keeps the state value when the configuration differs from it only in letter case."
}

func (m caseInsensitiveSet) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (caseInsensitiveSet) PlanModifySet(ctx context.Context, req planmodifier.SetRequest, resp *planmodifier.SetResponse) {
	if req.StateValue.IsNull() || req.StateValue.IsUnknown() || req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	lowered := func(set types.Set) map[string]bool {
		out := map[string]bool{}
		for _, element := range set.Elements() {
			value, ok := element.(types.String)
			if !ok || value.IsUnknown() {
				return nil
			}
			out[strings.ToLower(strings.TrimSpace(value.ValueString()))] = true
		}
		return out
	}
	planned, stored := lowered(req.ConfigValue), lowered(req.StateValue)
	if planned == nil || stored == nil || len(planned) != len(stored) {
		return
	}
	for value := range planned {
		if !stored[value] {
			return
		}
	}
	resp.PlanValue = req.StateValue
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

func attributePath(pointer, member string, body any) (path.Path, bool) {
	segments := strings.Split(strings.TrimPrefix(pointer, "/"), "/")
	if pointer == "" || segments[0] == "" {
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
	case member:
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

func addNotificationWriteError(diags *diag.Diagnostics, summary, noun, member string, body any, err error) {
	var apiErr *client.APIError
	if !asAPIError(err, &apiErr) {
		diags.AddError(summary, err.Error())
		return
	}
	pointer := apiErr.Detail("pointer")
	if pointer == "" && apiErr.Detail("attribute") != "" {
		pointer = "/" + strings.ReplaceAll(apiErr.Detail("attribute"), ".", "/")
	}
	at, mapped := attributePath(pointer, member, body)
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
		reason += fmt.Sprintf(" (%q)", value)
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
