//go:build actinternal

package provider_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

func deploymentsConfig(extra string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_aws_onboarding_parameters" "account" {
  account_id = %q
}

data "act_aws_onboarding_parameters" "org" {
  organization_id = %q
}

resource "act_aws_account_deployment" "this" {
  deployment_id = data.act_aws_onboarding_parameters.account.deployment_id
  account_id    = %q
  role_arn      = data.act_aws_onboarding_parameters.account.role_arn
  tags          = { team = "platform" }
}

resource "act_aws_organization_deployment" "this" {
  deployment_id       = data.act_aws_onboarding_parameters.org.deployment_id
  organization_id     = %q
  role_arn            = %q
  root_id             = %q
  deletion_protection = false
}
%s
`, testAccount, testOrg, testAccount, testOrg, roleArn(otherAccount), testRoot, extra)
}

const deploymentReads = `
data "act_deployment" "by_target" {
  target = act_aws_account_deployment.this.account_id
}

data "act_deployment" "by_id" {
  id = act_aws_organization_deployment.this.id
}

data "act_deployments" "aws" {
  cloud      = "aws"
  depends_on = [act_aws_account_deployment.this, act_aws_organization_deployment.this]
}

data "act_deployments" "platform" {
  tags       = { team = "platform" }
  depends_on = [act_aws_account_deployment.this, act_aws_organization_deployment.this]
}

data "act_deployment_coverage" "org" {
  deployment_id = act_aws_organization_deployment.this.id
}

data "act_deployment_accounts" "failed" {
  deployment_id = act_aws_organization_deployment.this.id
  status        = "failed"
}

data "act_deployment_accounts" "account" {
  deployment_id = act_aws_account_deployment.this.id
}
`

func TestDeploymentDataSources(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	accountID := s.DeploymentID("aws:account:"+testAccount, "")
	orgID := s.DeploymentID("aws:organization:"+testOrg, "")
	failing := "ROLE_MISSING"
	s.SetMemberAccounts(orgID, []gen.MemberAccount{
		{AccountID: "333333333333", Status: gen.MemberAccountStatusConnected},
		{AccountID: "444444444444", Status: gen.MemberAccountStatusFailed, ErrorCode: &failing},
		{AccountID: "555555555555", Status: gen.MemberAccountStatusPending},
		{AccountID: "666666666666", Status: gen.MemberAccountStatusExcluded},
	})

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: deploymentsConfig("")},
			{
				Config: deploymentsConfig(deploymentReads),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.act_deployment.by_target", tfjsonpath.New("id"), knownvalue.StringExact(accountID)),
					statecheck.ExpectKnownValue("data.act_deployment.by_target", tfjsonpath.New("scope"), knownvalue.StringExact("account")),
					statecheck.ExpectKnownValue("data.act_deployment.by_target", tfjsonpath.New("cloud"), knownvalue.StringExact("aws")),
					statecheck.ExpectKnownValue("data.act_deployment.by_id", tfjsonpath.New("scope"), knownvalue.StringExact("organization")),
					statecheck.ExpectKnownValue("data.act_deployment.by_id", tfjsonpath.New("targets"), knownvalue.ListExact([]knownvalue.Check{
						knownvalue.StringExact(testOrg), knownvalue.StringExact(testRoot),
					})),
					statecheck.ExpectKnownValue("data.act_deployments.aws", tfjsonpath.New("ids"), knownvalue.ListSizeExact(2)),
					statecheck.ExpectKnownValue("data.act_deployments.platform", tfjsonpath.New("ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(accountID)})),
					statecheck.ExpectKnownValue("data.act_deployments.platform", tfjsonpath.New("deployments").AtSliceIndex(0).AtMapKey("tags").AtMapKey("team"), knownvalue.StringExact("platform")),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("accounts_expected"), knownvalue.Int64Exact(3)),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("accounts_connected"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("accounts_failed"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("accounts_pending"), knownvalue.Int64Exact(1)),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("discovery_state"), knownvalue.StringExact("complete")),
					statecheck.ExpectKnownValue("data.act_deployment_coverage.org", tfjsonpath.New("failed_accounts").AtSliceIndex(0).AtMapKey("account_id"), knownvalue.StringExact("444444444444")),
					statecheck.ExpectKnownValue("data.act_deployment_accounts.failed", tfjsonpath.New("account_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact("444444444444")})),
					statecheck.ExpectKnownValue("data.act_deployment_accounts.failed", tfjsonpath.New("accounts").AtSliceIndex(0).AtMapKey("error_code"), knownvalue.StringExact(failing)),
					statecheck.ExpectKnownValue("data.act_deployment_accounts.account", tfjsonpath.New("account_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(testAccount)})),
				},
			},
		},
	})
}

func TestDeploymentDataSourceNeedsExactlyOneMatch(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

data "act_deployment" "missing" {
  target = "999999999999"
}
`,
			ExpectError: regexp.MustCompile(`No deployment in this tenant matches 999999999999`),
		}},
	})
}

func TestAwsOnboardingParametersNeedsOneTarget(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

data "act_aws_onboarding_parameters" "both" {
  account_id      = "111111111111"
  organization_id = "o-abcdefghij"
}
`,
			ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
		}},
	})
}

func TestAwsOnboardingParametersForAnAccount(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	id := s.DeploymentID("aws:account:"+testAccount, "")
	address := "data.act_aws_onboarding_parameters.this"

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: requiredProviders + `
provider "act" {}

data "act_aws_onboarding_parameters" "this" {
  account_id = "` + testAccount + `"
}
`,
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(address, tfjsonpath.New("deployment_id"), knownvalue.StringExact(id)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("role_name"), knownvalue.StringExact("ActSecurityRole-"+id)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("role_arn"), knownvalue.StringExact("arn:aws:iam::"+testAccount+":role/ActSecurityRole-"+id)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("act_principal_arn"), knownvalue.StringExact(fakeapi.ActPrincipalArn)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("deprecated_principal_arns"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(fakeapi.DeprecatedPrincipal)})),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("external_id_source"), knownvalue.StringExact("derived")),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("external_id_key_version"), knownvalue.Int64Exact(fakeapi.ExternalIDKeyVersion)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("managed_policy_arns"), knownvalue.ListSizeExact(1)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("custom_policy_documents"), knownvalue.MapSizeExact(1)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("module_source"), knownvalue.StringExact(fakeapi.ModuleSource)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("module_versions").AtSliceIndex(0).AtMapKey("version"), knownvalue.StringExact(fakeapi.ModuleVersion)),
				statecheck.ExpectKnownValue(address, tfjsonpath.New("existing_deployment"), knownvalue.Null()),
			},
		}},
	})
}
