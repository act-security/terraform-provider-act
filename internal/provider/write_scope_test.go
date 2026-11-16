//go:build actinternal

package provider_test

import (
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

func TestAReadOnlyKeyFailsAPendingCreateAtPlan(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsPlanKey))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      accountConfig(""),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`(?s)creates the resource, which needs the deployments:write scope.*holds\s+deployments:read`),
		}},
	})

	if n := countRequests(s, "POST", "/v1/deployments/aws"); n != 0 {
		t.Fatalf("the provider sent %d create requests, want none", n)
	}
}

func TestPlanOnlyTurnsTheMissingWriteScopeIntoAWarning(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsPlanKey))
	s.Setenv(t)
	t.Setenv("ACT_PLAN_ONLY", "true")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:             accountConfig(""),
			PlanOnly:           true,
			ExpectNonEmptyPlan: true,
		}},
	})
}

func TestARejectedPlanOnlyValueStopsTheProvider(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	t.Setenv("ACT_PLAN_ONLY", "sometimes")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      accountConfig(""),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`ACT_PLAN_ONLY must be true or false`),
		}},
	})
}

func TestTheTerraformDeploymentsKeysPlanWithReadAndApplyWithWrite(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsApplyKey))
	s.Setenv(t)
	provider.FastVerification(t)

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
				Config:      accountConfig(`  tags = { team = "platform" }`),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`changes the resource, which needs the deployments:write scope`),
			},
			{
				PreConfig: func() { s.UseKey(fakeapi.TerraformDeploymentsApplyKey) },
				Config:    accountConfig(`  tags = { team = "platform" }`),
				ConfigPlanChecks: resource.ConfigPlanChecks{
					PreApply: []plancheck.PlanCheck{plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionUpdate)},
				},
			},
			{
				PreConfig:   func() { s.UseKey(fakeapi.TerraformDeploymentsPlanKey) },
				Config:      requiredProviders + "\nprovider \"act\" {}\n",
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`destroys the resource, which needs the deployments:write scope`),
			},
			{
				PreConfig: func() { s.UseKey(fakeapi.TerraformDeploymentsApplyKey) },
				Config:    requiredProviders + "\nprovider \"act\" {}\n",
			},
		},
	})
}

func TestADeploymentsKeyCannotPlanAnIntegration(t *testing.T) {
	s := fakeapi.Start(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsApplyKey))
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      slackWriteOnly("xoxb-not-a-real-token", 1),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`creates the resource, which needs the integrations:write scope`),
		}},
	})
}
