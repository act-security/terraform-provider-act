//go:build actinternal

package provider_test

import (
	"net/http"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

func publicAPIWrites(s *fakeapi.Servers) int {
	n := 0
	for _, r := range s.Recorder().Requests() {
		if r.Origin == fakeapi.OriginAPI && r.Method != http.MethodGet {
			n++
		}
	}
	return n
}

func TestAReadOnlyKeyPlansAPendingCreateAndTheApplyStopsBeforeCallingAct(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsPlanKey))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:             accountConfig(""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config:      accountConfig(""),
				ExpectError: regexp.MustCompile(`(?s)This apply creates act_aws_account_deployment, which needs the\s+deployments:write\s+scope.*holds\s+deployments:read.*Nothing was sent to Act`),
			},
		},
	})

	if n := publicAPIWrites(s); n != 0 {
		t.Fatalf("the provider sent %d write requests with a read-only key, want none", n)
	}
}

func TestTheTerraformDeploymentsKeysPlanWithReadAndApplyWithWrite(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsApplyKey))
	s.Setenv(t)
	provider.FastVerification(t)
	tagged := accountConfig(`  tags = { team = "platform" }`)
	noResources := requiredProviders + "\nprovider \"act\" {}\n"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: accountConfig(""),
			},
			{
				PreConfig: func() { s.UseKey(fakeapi.TerraformDeploymentsPlanKey) },
				Config:    accountConfig(""),
				PlanOnly:  true,
			},
			{
				Config:             tagged,
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config:      tagged,
				ExpectError: regexp.MustCompile(`This apply changes act_aws_account_deployment`),
			},
			{
				PreConfig: func() { s.UseKey(fakeapi.TerraformDeploymentsApplyKey) },
				Config:    tagged,
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionUpdate)},
				},
			},
			{
				PreConfig:   func() { s.UseKey(fakeapi.TerraformDeploymentsPlanKey) },
				Config:      noResources,
				ExpectError: regexp.MustCompile(`This apply destroys act_aws_account_deployment`),
			},
			{
				PreConfig: func() { s.UseKey(fakeapi.TerraformDeploymentsApplyKey) },
				Config:    noResources,
			},
		},
	})
}

func TestADeploymentsKeyCannotApplyAnIntegration(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsApplyKey))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      slackWriteOnly("xoxb-not-a-real-token", 1),
			ExpectError: regexp.MustCompile(`(?s)This apply creates act_slack_integration, which needs the\s+integrations:write\s+scope.*whose role grants\s+integrations:write`),
		}},
	})

	if n := publicAPIWrites(s); n != 0 {
		t.Fatalf("the provider sent %d write requests without integrations:write, want none", n)
	}
}
