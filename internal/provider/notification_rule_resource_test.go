//go:build actinternal

package provider_test

import (
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

const ruleAddress = "act_notification_rule.this"

type ruleConfig struct {
	name       string
	enabled    string
	recipients string
	slack      bool
	condition  bool
}

func notificationRuleConfig(slackID string, c ruleConfig) string {
	enabled := ""
	if c.enabled != "" {
		enabled = "  enabled = " + c.enabled + "\n"
	}
	condition := ""
	if c.condition {
		condition = `
  condition {
    event_type = "simulation.finished"
    field      = "source"
    values     = ["policy_mgmt", "campaigns"]
  }
`
	}
	slack := ""
	if c.slack {
		slack = `
  slack {
    integration_id = "` + slackID + `"
    channel_ids    = [data.act_slack_channel.alerts.id, "C0PLATFORM1"]
  }
`
	}
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_email_integration" "this" {}

data "act_slack_channel" "alerts" {
  name = "#Security-Alerts"
}

resource "act_notification_recipient" "oncall" {
  name = "On-call"

  email {
    integration_id = data.act_email_integration.this.id
    recipients     = ["oncall@acme.com"]
  }
}

resource "act_notification_rule" "this" {
  name          = %q
%s  event_types   = ["simulation.finished", "policy.drift_detected"]
  recipient_ids = [act_notification_recipient.oncall.id]
%s
  email {
    integration_id = data.act_email_integration.this.id
    recipients     = [%s]
  }
%s}
`, c.name, enabled, condition, c.recipients, slack)
}

func ruleIDOf(s *terraform.State) string {
	return s.RootModule().Resources[ruleAddress].Primary.ID
}

func TestNotificationRuleLifecycle(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	slackID := s.SeedIntegration("slack", "xoxb-seeded")
	var id string
	full := ruleConfig{name: "Simulations", recipients: `"Lee@Acme.com", "ops@acme.com"`, slack: true, condition: true}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: notificationRuleConfig(slackID, full),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("enabled"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("revision"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("min_client_revision"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("created_via"), knownvalue.StringExact("api")),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("web_url"), knownvalue.NotNull()),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("email").AtSliceIndex(0).AtMapKey("recipients"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact("Lee@Acme.com"),
						knownvalue.StringExact("ops@acme.com"),
					})),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("condition").AtSliceIndex(0).AtMapKey("operator"), knownvalue.StringExact("in")),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("slack").AtSliceIndex(0).AtMapKey("channel_ids"), knownvalue.SetExact([]knownvalue.Check{
						knownvalue.StringExact(fakeapi.SlackChannelSecurityID),
						knownvalue.StringExact(fakeapi.SlackChannelPlatformID),
					})),
				},
				Check: func(st *terraform.State) error {
					id = ruleIDOf(st)
					rule, ok := s.NotificationRule(id)
					if !ok {
						return fmt.Errorf("rule %s is missing from the fake", id)
					}
					if len(rule.Actions) != 2 || rule.Actions[0].Email == nil || string(rule.Actions[0].Email.Recipients[0]) != "lee@acme.com" {
						return fmt.Errorf("Act holds actions %+v", rule.Actions)
					}
					if len(rule.RecipientIds) != 1 || len(rule.Conditions) != 1 {
						return fmt.Errorf("Act holds recipients %v and conditions %v", rule.RecipientIds, rule.Conditions)
					}
					return nil
				},
			},
			{
				Config:   notificationRuleConfig(slackID, ruleConfig{name: "Simulations", recipients: `"ops@acme.com", "LEE@acme.com"`, slack: true, condition: true}),
				PlanOnly: true,
			},
			{
				Config: notificationRuleConfig(slackID, ruleConfig{name: "Simulations", enabled: "false", recipients: `"lee@acme.com"`}),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("revision"), knownvalue.Int64Exact(2)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("slack"), knownvalue.ListSizeExact(0)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("condition"), knownvalue.ListSizeExact(0)),
				},
				Check: func(*terraform.State) error {
					if omitted := s.LastRuleReplaceOmitted(); len(omitted) > 0 {
						return fmt.Errorf("the update left out %v, so Act kept their stored values", omitted)
					}
					rule, _ := s.NotificationRule(id)
					if rule.Enabled || len(rule.Actions) != 1 || len(rule.Conditions) != 0 {
						return fmt.Errorf("Act holds enabled=%t actions=%+v conditions=%+v", rule.Enabled, rule.Actions, rule.Conditions)
					}
					return nil
				},
			},
			{
				PreConfig: func() {
					if !s.RenameNotificationRuleOutOfBand(id, "Renamed in the console") {
						t.Fatal("the rule is missing from the fake")
					}
				},
				Config: notificationRuleConfig(slackID, ruleConfig{name: "Simulations", enabled: "false", recipients: `"lee@acme.com"`}),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("name"), knownvalue.StringExact("Simulations")),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("revision"), knownvalue.Int64Exact(4)),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("last_modified_via"), knownvalue.StringExact("api")),
				},
			},
			{
				ResourceName:            ruleAddress,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"email.0.recipients"},
			},
			{
				PreConfig: func() { s.DeleteNotificationRuleOutOfBand(id) },
				Config:    notificationRuleConfig(slackID, ruleConfig{name: "Simulations", enabled: "false", recipients: `"lee@acme.com"`}),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(ruleAddress, plancheck.ResourceActionCreate),
				}},
			},
		},
	})
}

func TestNotificationRuleUpdateFailsWhenTheRuleChangedAfterThePlan(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	slackID := s.SeedIntegration("slack", "xoxb-seeded")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: notificationRuleConfig(slackID, ruleConfig{name: "First", recipients: `"lee@acme.com"`})},
			{
				PreConfig:   func() { s.EditNotificationRuleBeforeNextReplace("Edited during the apply") },
				Config:      notificationRuleConfig(slackID, ruleConfig{name: "Second", recipients: `"lee@acme.com"`}),
				ExpectError: regexp.MustCompile(`changed in Act since Terraform last read it`),
			},
			{
				Config: notificationRuleConfig(slackID, ruleConfig{name: "Second", recipients: `"lee@acme.com"`}),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("name"), knownvalue.StringExact("Second")),
					statecheck.ExpectKnownValue(ruleAddress, tfjsonpath.New("revision"), knownvalue.Int64Exact(3)),
				},
			},
		},
	})
}

func TestNotificationRuleCreateRetriesWithTheSameIdempotencyKey(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	slackID := s.SeedIntegration("slack", "xoxb-seeded")
	s.LoseNextNotificationRuleCreateReply()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: notificationRuleConfig(slackID, ruleConfig{name: "Retried", recipients: `"lee@acme.com"`}),
			Check: func(st *terraform.State) error {
				if got := s.NotificationRuleCreateRequests(); got != 2 {
					return fmt.Errorf("the provider sent %d create requests, want 2", got)
				}
				if got := s.NotificationRuleCount(); got != 1 {
					return fmt.Errorf("Act holds %d rules after the retry, want 1", got)
				}
				if _, ok := s.NotificationRule(ruleIDOf(st)); !ok {
					return fmt.Errorf("the state holds a rule Act does not have")
				}
				return nil
			},
		}},
	})
}

func TestNotificationRecipientLifecycleAndInUse(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	slackID := s.SeedIntegration("slack", "xoxb-seeded")
	const address = "act_notification_recipient.this"
	recipient := func(name string) string {
		return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_email_integration" "this" {}

resource "act_notification_recipient" "this" {
  name = %q

  email {
    integration_id = data.act_email_integration.this.id
    recipients     = ["Platform@Acme.com"]
  }

  slack {
    integration_id = %q
    channel_ids    = ["C0PLATFORM1"]
  }
}
`, name, slackID)
	}
	var id, ruleID string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: recipient("Platform team"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("revision"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("rule_ids"), knownvalue.SetSizeExact(0)),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("email").AtSliceIndex(0).AtMapKey("recipients"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("Platform@Acme.com")})),
				},
				Check: captureID(address, &id),
			},
			{
				Config: recipient("Platform"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("revision"), knownvalue.Int64Exact(2)),
				},
			},
			{
				ResourceName:            address,
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"email.0.recipients"},
			},
			{
				PreConfig: func() { ruleID = s.SeedNotificationRule("Made in the console", id) },
				Config:    recipient("Platform"),
				Check: func(st *terraform.State) error {
					got := st.RootModule().Resources[address].Primary.Attributes["rule_ids.0"]
					if got != ruleID {
						return fmt.Errorf("rule_ids holds %q, want %q", got, ruleID)
					}
					return nil
				},
			},
			{
				Config:      requiredProviders + "provider \"act\" {}\n",
				ExpectError: regexp.MustCompile(`still named by notification\s+rules`),
			},
			{
				PreConfig: func() { s.DeleteNotificationRuleOutOfBand(ruleID) },
				Config:    requiredProviders + "provider \"act\" {}\n",
			},
		},
	})
}

func TestNotificationRuleWriteErrors(t *testing.T) {
	tests := []struct {
		name    string
		opts    []fakeapi.Option
		rule    string
		want    string
		noSlack bool
	}{
		{
			name: "notification rules not enabled",
			opts: []fakeapi.Option{fakeapi.WithNotificationRulesDisabled()},
			rule: `event_types = ["connector.unhealthy"]`,
			want: `not enabled for this tenant`,
		},
		{
			name: "unknown recipient",
			rule: `event_types = ["connector.unhealthy"]
  recipient_ids = ["00000000-0000-4000-8000-00000000dead"]`,
			want: `unknown_recipient\s+\("00000000-0000-4000-8000-00000000dead"\)`,
		},
		{
			name: "condition on an event type the rule does not have",
			rule: `event_types = ["connector.unhealthy"]
  condition {
    event_type = "simulation.finished"
    field      = "source"
    values     = ["campaigns"]
  }`,
			want: `condition_event_type_not_in_rule`,
		},
		{
			name: "event type Act does not offer",
			rule: `event_types = ["violation.created"]`,
			want: `event_type_not_available\s+\("violation.created"\)`,
		},
		{
			name: "Slack integration that is not installed",
			rule: `event_types = ["connector.unhealthy"]
  slack {
    integration_id = "00000000-0000-4000-8000-0000000000ff"
    channel_ids    = ["C0PLATFORM1"]
  }`,
			want: `00000000-0000-4000-8000-0000000000ff is not installed or not\s+connected`,
		},
		{
			name: "Slack channel name instead of an ID",
			rule: `event_types = ["connector.unhealthy"]
  slack {
    integration_id = "00000000-0000-4000-8000-0000000000ff"
    channel_ids    = ["#security"]
  }`,
			want: `must be a Slack channel\s+ID`,
		},
		{
			name: "two email blocks",
			rule: `event_types = ["connector.unhealthy"]
  email {
    integration_id = "` + fakeapi.EmailIntegrationID + `"
    recipients     = ["a@acme.com"]
  }
  email {
    integration_id = "` + fakeapi.EmailIntegrationID + `"
    recipients     = ["b@acme.com"]
  }`,
			want: `at most 1`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeapi.Start(t, tt.opts...)
			s.Setenv(t)
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: factories(),
				Steps: []resource.TestStep{{
					Config: requiredProviders + `
provider "act" {}

resource "act_notification_rule" "this" {
  name = "Broken"
  ` + tt.rule + `
}
`,
					ExpectError: regexp.MustCompile(tt.want),
				}},
			})
		})
	}
}

func TestNotificationDataSources(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	s.SeedIntegration("slack", "xoxb-seeded")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: requiredProviders + `
provider "act" {}

data "act_email_integration" "this" {}

data "act_slack_channel" "by_name" {
  name = "#SECURITY-ALERTS"
}

data "act_slack_channel" "by_id" {
  name = "C0PLATFORM1"
}

data "act_notification_event_types" "all" {}
`,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.act_email_integration.this", tfjsonpath.New("id"), knownvalue.StringExact(fakeapi.EmailIntegrationID)),
					statecheck.ExpectKnownValue("data.act_slack_channel.by_name", tfjsonpath.New("id"), knownvalue.StringExact(fakeapi.SlackChannelSecurityID)),
					statecheck.ExpectKnownValue("data.act_slack_channel.by_name", tfjsonpath.New("channel_name"), knownvalue.StringExact(fakeapi.SlackChannelSecurityName)),
					statecheck.ExpectKnownValue("data.act_slack_channel.by_id", tfjsonpath.New("channel_name"), knownvalue.StringExact(fakeapi.SlackChannelPlatformName)),
					statecheck.ExpectKnownValue("data.act_notification_event_types.all", tfjsonpath.New("event_types"), knownvalue.ListSizeExact(4)),
					statecheck.ExpectKnownValue("data.act_notification_event_types.all", tfjsonpath.New("event_types").AtSliceIndex(2).AtMapKey("condition_fields").AtSliceIndex(0), knownvalue.ObjectExact(map[string]knownvalue.Check{
						"field":    knownvalue.StringExact("source"),
						"operator": knownvalue.StringExact("in"),
						"values":   knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("campaigns"), knownvalue.StringExact("policy_mgmt")}),
					})),
					statecheck.ExpectKnownValue("data.act_notification_event_types.all", tfjsonpath.New("limits").AtMapKey("max_recipients_per_rule"), knownvalue.Int64Exact(20)),
				},
			},
			{
				Config: requiredProviders + `
provider "act" {}

data "act_slack_channel" "missing" {
  name = "#nowhere"
}
`,
				ExpectError: regexp.MustCompile(`No channel named "#nowhere"`),
			},
		},
	})
}

func TestSlackChannelNeedsSlack(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

data "act_slack_channel" "alerts" {
  name = "security-alerts"
}
`,
			ExpectError: regexp.MustCompile(`Slack is not connected`),
		}},
	})
}

func TestNotificationRuleWithoutChangesWritesNothing(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	slackID := s.SeedIntegration("slack", "xoxb-seeded")
	config := notificationRuleConfig(slackID, ruleConfig{name: "Quiet", recipients: `"Lee@acme.com"`})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: config},
			{Config: config},
			{Config: config, PlanOnly: true},
		},
	})
	writes := map[string]int{}
	for _, r := range s.Recorder().Requests() {
		if r.Origin == fakeapi.OriginAPI && r.Method != http.MethodGet {
			writes[r.Method+" "+strings.Join(strings.Split(r.Path, "/")[:3], "/")]++
		}
	}
	want := map[string]int{"POST /v1/notification-recipients": 1, "POST /v1/notification-rules": 1, "DELETE /v1/notification-rules": 1, "DELETE /v1/notification-recipients": 1}
	if !maps.Equal(writes, want) {
		t.Fatalf("writes = %v, want %v", writes, want)
	}
}
