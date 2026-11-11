//go:build actinternal

package provider_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"
	"github.com/hashicorp/terraform-plugin-testing/tfversion"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

const slackAddress = "act_slack_integration.this"

func slackWriteOnly(token string, version int) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

resource "act_slack_integration" "this" {
  bot_token_wo         = %q
  bot_token_wo_version = %d
}
`, token, version)
}

func noStoredValue(values ...string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		for _, module := range s.Modules {
			for address, res := range module.Resources {
				for key, value := range res.Primary.Attributes {
					for _, secret := range values {
						if strings.Contains(value, secret) {
							return fmt.Errorf("%s.%s holds a secret in the state", address, key)
						}
					}
				}
			}
		}
		return nil
	}
}

func captureID(address string, into *string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		res, ok := s.RootModule().Resources[address]
		if !ok {
			return fmt.Errorf("%s is not in the state", address)
		}
		*into = res.Primary.ID
		return nil
	}
}

func TestSlackIntegrationWriteOnlyLifecycle(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
		Steps: []resource.TestStep{
			{
				Config: slackWriteOnly("xoxb-first", 1),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(slackAddress, tfjsonpath.New("status"), knownvalue.StringExact("connected")),
					statecheck.ExpectKnownValue(slackAddress, tfjsonpath.New("bot_token"), knownvalue.Null()),
					statecheck.ExpectKnownValue(slackAddress, tfjsonpath.New("bot_token_wo"), knownvalue.Null()),
					statecheck.ExpectKnownValue(slackAddress, tfjsonpath.New("bot_token_wo_version"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue(slackAddress, tfjsonpath.New("bot_token_updated_at"), knownvalue.NotNull()),
				},
				Check: resource.ComposeTestCheckFunc(noStoredValue("xoxb-first"), captureID(slackAddress, &id), func(*terraform.State) error {
					if got, _ := s.IntegrationSecret(id); got != "xoxb-first" {
						return fmt.Errorf("Act holds %q, want the configured token", got)
					}
					return nil
				}),
			},
			{
				Config:   slackWriteOnly("xoxb-first", 1),
				PlanOnly: true,
			},
			{
				Config: slackWriteOnly("xoxb-second", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(slackAddress, plancheck.ResourceActionUpdate),
				}},
				Check: resource.ComposeTestCheckFunc(noStoredValue("xoxb-second"), func(st *terraform.State) error {
					if st.RootModule().Resources[slackAddress].Primary.ID != id {
						return fmt.Errorf("rotation replaced the integration")
					}
					if got, _ := s.IntegrationSecret(id); got != "xoxb-second" {
						return fmt.Errorf("Act holds %q after the rotation", got)
					}
					return nil
				}),
			},
			{
				PreConfig: func() {
					if !s.RotateIntegrationSecretOutOfBand(id, "xoxb-set-in-the-console") {
						t.Fatal("the integration is missing from the fake")
					}
				},
				Config: slackWriteOnly("xoxb-second", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(slackAddress, plancheck.ResourceActionUpdate),
				}},
				Check: func(*terraform.State) error {
					if got, _ := s.IntegrationSecret(id); got != "xoxb-second" {
						return fmt.Errorf("Act holds %q, want the configured token sent again", got)
					}
					return nil
				},
			},
			{
				ResourceName:            slackAddress,
				ImportState:             true,
				ImportStateId:           "slack",
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"bot_token_wo_version"},
			},
			{
				PreConfig: func() { s.DeleteIntegrationOutOfBand(id) },
				Config:    slackWriteOnly("xoxb-second", 2),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(slackAddress, plancheck.ResourceActionCreate),
				}},
			},
		},
	})
}

func jiraPlaintext(email, token string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

resource "act_jira_integration" "this" {
  base_url  = "https://acme.atlassian.net"
  email     = %q
  api_token = %q
}
`, email, token)
}

func TestJiraIntegrationSensitivePathSendsTheSecretWithEveryValueChange(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	var id string

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: jiraPlaintext("bot@acme.io", "jira-token-1"),
				Check:  captureID("act_jira_integration.this", &id),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("act_jira_integration.this", tfjsonpath.New("email"), knownvalue.StringExact("bot@acme.io")),
				},
			},
			{
				Config: jiraPlaintext("ops@acme.io", "jira-token-1"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction("act_jira_integration.this", plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("act_jira_integration.this", tfjsonpath.New("email"), knownvalue.StringExact("ops@acme.io")),
				},
				Check: func(*terraform.State) error {
					if got, _ := s.IntegrationSecret(id); got != "jira-token-1" {
						return fmt.Errorf("Act holds %q", got)
					}
					return nil
				},
			},
		},
	})
}

func TestSplunkIntegrationDefaultsToVerifiedTLS(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

resource "act_splunk_integration" "this" {
  hec_url   = "https://http-inputs-acme.splunkcloud.com"
  hec_token = "hec-token"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("act_splunk_integration.this", tfjsonpath.New("tls_verification"), knownvalue.StringExact("verify")),
			},
		}},
	})
}

func TestIntegrationWriteErrors(t *testing.T) {
	tests := []struct {
		name   string
		before func(t *testing.T, s *fakeapi.Servers)
		config string
		want   string
	}{
		{
			name: "second install of a type",
			before: func(t *testing.T, s *fakeapi.Servers) {
				t.Helper()
				s.SeedIntegration("slack", "xoxb-existing")
			},
			config: slackWriteOnly("xoxb-another", 1),
			want:   `already has a Slack integration`,
		},
		{
			name:   "rejected credentials",
			config: slackWriteOnly(fakeapi.ConnectionCheckFailureTrigger, 1),
			want:   `Act could not connect with these settings`,
		},
		{
			name: "both the sensitive and the write-only token",
			config: requiredProviders + `
provider "act" {}
resource "act_slack_integration" "this" {
  bot_token            = "xoxb-a"
  bot_token_wo         = "xoxb-b"
  bot_token_wo_version = 1
}
`,
			want: `Invalid Attribute Combination`,
		},
		{
			name: "no token at all",
			config: requiredProviders + `
provider "act" {}
resource "act_slack_integration" "this" {}
`,
			want: `Missing Attribute Configuration`,
		},
		{
			name: "a write-only token without its version",
			config: requiredProviders + `
provider "act" {}
resource "act_slack_integration" "this" {
  bot_token_wo = "xoxb-a"
}
`,
			want: `bot_token_wo_version`,
		},
		{
			name:   "not a bot token",
			config: slackWriteOnly("xoxp-user-token", 1),
			want:   `must start with xoxb-`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := fakeapi.Start(t)
			s.Setenv(t)
			if tt.before != nil {
				tt.before(t, s)
			}
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: factories(),
				TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
				Steps:                    []resource.TestStep{{Config: tt.config, ExpectError: regexp.MustCompile(tt.want)}},
			})
		})
	}
}

func TestIntegrationDataSources(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

data "act_integration" "email" {
  type = "email"
}

data "act_integration_types" "all" {}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue("data.act_integration.email", tfjsonpath.New("id"), knownvalue.StringExact(fakeapi.EmailIntegrationID)),
				statecheck.ExpectKnownValue("data.act_integration.email", tfjsonpath.New("status"), knownvalue.StringExact("connected")),
				statecheck.ExpectKnownValue("data.act_integration_types.all", tfjsonpath.New("types"), knownvalue.ListSizeExact(5)),
				statecheck.ExpectKnownValue("data.act_integration_types.all", tfjsonpath.New("types").AtSliceIndex(0).AtMapKey("fields").AtSliceIndex(0), knownvalue.ObjectExact(map[string]knownvalue.Check{
					"name":      knownvalue.StringExact("botToken"),
					"sensitive": knownvalue.Bool(true),
				})),
			},
		}},
	})
}
