package provider

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

func sampleRuleWrite() apigen.NotificationRuleWrite {
	conditions := []apigen.NotificationCondition{{EventType: "simulation.finished", Field: "source", Operator: "in", Values: []string{"campaigns"}}}
	actions := []apigen.NotificationAction{
		{Type: apigen.NotificationActionTypeEmail, Email: &apigen.NotificationEmailAction{IntegrationID: "e", Recipients: []openapi_types.Email{"Lee@Acme.com"}}},
		{Type: apigen.NotificationActionTypeSlack, Slack: &apigen.NotificationSlackAction{IntegrationID: "s", ChannelIds: []string{"C1", "#ops"}}},
	}
	recipients := []string{"r-0", "r-1"}
	return apigen.NotificationRuleWrite{
		Name:         "rule",
		EventTypes:   []string{"simulation.finished"},
		Conditions:   &conditions,
		Actions:      &actions,
		RecipientIds: &recipients,
	}
}

func TestAttributePath(t *testing.T) {
	body := sampleRuleWrite()
	tests := []struct {
		pointer string
		want    path.Path
		ok      bool
	}{
		{"/name", path.Root("name"), true},
		{"/eventTypes/0", path.Root("event_types").AtSetValue(types.StringValue("simulation.finished")), true},
		{"/eventTypes", path.Root("event_types"), true},
		{"/recipientIds/1", path.Root("recipient_ids").AtSetValue(types.StringValue("r-1")), true},
		{"/conditions/0/eventType", path.Root("condition").AtListIndex(0).AtName("event_type"), true},
		{"/conditions/0/values/0", path.Root("condition").AtListIndex(0).AtName("values").AtSetValue(types.StringValue("campaigns")), true},
		{"/conditions/3", path.Root("condition").AtListIndex(3), true},
		{"/actions/1/slack/channelIds", path.Root("slack").AtListIndex(0).AtName("channel_ids"), true},
		{"/actions/1/slack/channelIds/1", path.Root("slack").AtListIndex(0).AtName("channel_ids").AtSetValue(types.StringValue("#ops")), true},
		{"/actions/0/email/integrationId", path.Root("email").AtListIndex(0).AtName("integration_id"), true},
		{"/actions/0/email/recipients/0", path.Root("email").AtListIndex(0).AtName("recipients").AtSetValue(types.StringValue("Lee@Acme.com")), true},
		{"/actions/1", path.Root("slack").AtListIndex(0), true},
		{"/actions/0/email", path.Root("email").AtListIndex(0), true},
		{"/actions/1/teams", path.Empty(), false},
		{"/methods/0/email", path.Empty(), false},
		{"/unknown", path.Empty(), false},
		{"", path.Empty(), false},
	}
	for _, tt := range tests {
		got, ok := attributePath(tt.pointer, "actions", body)
		if ok != tt.ok || !got.Equal(tt.want) {
			t.Errorf("attributePath(%q) = %s, %t; want %s, %t", tt.pointer, got, ok, tt.want, tt.ok)
		}
	}
	recipient := apigen.NotificationRecipientWrite{Name: "r", Methods: (*body.Actions)[1:]}
	if got, ok := attributePath("/methods/0/slack/channelIds/0", "methods", recipient); !ok || !got.Equal(path.Root("slack").AtListIndex(0).AtName("channel_ids").AtSetValue(types.StringValue("C1"))) {
		t.Errorf("recipient pointer mapped to %s, %t", got, ok)
	}
}

func TestAddNotificationWriteError(t *testing.T) {
	body := sampleRuleWrite()
	tests := []struct {
		name     string
		err      error
		path     path.Path
		contains string
	}{
		{
			name:     "domain error with a pointer",
			err:      &client.APIError{Status: 400, Code: "invalid_request", Details: map[string]any{"reason": "channel_name_not_allowed", "pointer": "/actions/1/slack/channelIds/1"}},
			path:     path.Root("slack").AtListIndex(0).AtName("channel_ids").AtSetValue(types.StringValue("#ops")),
			contains: `channel_name_not_allowed ("#ops")`,
		},
		{
			name:     "schema error with a dotted attribute",
			err:      &client.APIError{Status: 400, Code: "invalid_request", Details: map[string]any{"attribute": "conditions.0.values", "issues": []any{map[string]any{"attribute": "conditions.0.values", "message": "Too small"}}}},
			path:     path.Root("condition").AtListIndex(0).AtName("values"),
			contains: "Too small",
		},
		{
			name:     "integration not connected",
			err:      &client.APIError{Status: 422, Code: "integration_not_connected", Details: map[string]any{"pointer": "/actions/0/email"}},
			path:     path.Root("email").AtListIndex(0),
			contains: "The integration e is not installed",
		},
		{
			name:     "feature disabled",
			err:      &client.APIError{Status: 403, Code: "feature_disabled", Details: map[string]any{"feature": "notification_rules"}},
			contains: "not enabled for this tenant",
		},
		{
			name:     "stale revision",
			err:      &client.APIError{Status: http.StatusPreconditionFailed, Code: "precondition_failed", Details: map[string]any{"etag": `"4"`}},
			contains: "changed in Act since Terraform last read it",
		},
		{
			name:     "taken name",
			err:      &client.APIError{Status: 409, Code: "already_exists", Details: map[string]any{"attribute": "name"}},
			path:     path.Root("name"),
			contains: "already has this name",
		},
		{
			name:     "limit",
			err:      &client.APIError{Status: 422, Code: "limit_exceeded", Details: map[string]any{"reason": "enabled_rules_per_event_type", "eventType": "simulation.finished"}},
			contains: "enabled_rules_per_event_type for simulation.finished",
		},
		{
			name:     "transport error",
			err:      errors.New("connection reset"),
			contains: "connection reset",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var diags diag.Diagnostics
			addNotificationWriteError(&diags, "Could not create the notification rule", "notification rule", "actions", body, tt.err)
			if len(diags) != 1 {
				t.Fatalf("got %d diagnostics", len(diags))
			}
			if !strings.Contains(diags[0].Detail(), tt.contains) {
				t.Errorf("detail %q does not contain %q", diags[0].Detail(), tt.contains)
			}
			withPath, ok := diags[0].(diag.DiagnosticWithPath)
			if len(tt.path.Steps()) == 0 {
				if ok {
					t.Errorf("diagnostic points at %s, want no attribute", withPath.Path())
				}
				return
			}
			if !ok || !withPath.Path().Equal(tt.path) {
				t.Errorf("diagnostic path = %v, want %s", diags[0], tt.path)
			}
		})
	}
}

func TestKeepSpelling(t *testing.T) {
	got := keepSpelling([]string{"Lee@Acme.com", " Ops@Acme.com"}, []string{"lee@acme.com", "new@acme.com", "ops@acme.com"})
	want := []string{"Lee@Acme.com", "new@acme.com", " Ops@Acme.com"}
	if !slices.Equal(got, want) {
		t.Fatalf("keepSpelling = %q, want %q", got, want)
	}
}

func TestCaseInsensitiveSet(t *testing.T) {
	set := func(values ...string) types.Set {
		return stringSet(context.Background(), values, &diag.Diagnostics{})
	}
	tests := []struct {
		name          string
		config, state types.Set
		keepState     bool
	}{
		{"case only", set("LEE@acme.com", "ops@acme.com"), set("ops@acme.com", "lee@acme.com"), true},
		{"new address", set("lee@acme.com", "new@acme.com"), set("lee@acme.com"), false},
		{"swapped address", set("lee@acme.com", "new@acme.com"), set("lee@acme.com", "old@acme.com"), false},
		{"no state", set("lee@acme.com"), types.SetNull(types.StringType), false},
	}
	for _, tt := range tests {
		resp := &planmodifier.SetResponse{PlanValue: tt.config}
		caseInsensitiveSet{}.PlanModifySet(context.Background(), planmodifier.SetRequest{ConfigValue: tt.config, StateValue: tt.state, PlanValue: tt.config}, resp)
		if kept := resp.PlanValue.Equal(tt.state); kept != tt.keepState {
			t.Errorf("%s: kept state = %t, want %t", tt.name, kept, tt.keepState)
		}
	}
}

func TestWarnNewerRule(t *testing.T) {
	var diags diag.Diagnostics
	warnNewerRule(&diags, apigen.NotificationRule{ID: "r", Name: "n", MinClientRevision: supportedClientRevision})
	if len(diags) != 0 {
		t.Fatalf("a current rule warned: %v", diags)
	}
	warnNewerRule(&diags, apigen.NotificationRule{ID: "r", Name: "n", MinClientRevision: supportedClientRevision + 1})
	if len(diags) != 1 || diags[0].Severity() != diag.SeverityWarning || !strings.Contains(diags[0].Detail(), "needs client revision 2") {
		t.Fatalf("a newer rule gave %v", diags)
	}
}

func TestRevisionETag(t *testing.T) {
	if got := revisionETag(`"7"`, types.Int64Value(3)); got != `"7"` {
		t.Errorf("stored ETag not used: %s", got)
	}
	if got := revisionETag("", types.Int64Value(3)); got != `"3"` {
		t.Errorf("revision fallback = %s", got)
	}
}
