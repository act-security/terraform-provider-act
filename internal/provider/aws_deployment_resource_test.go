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

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

const (
	testAccount    = "111111111111"
	otherAccount   = "222222222222"
	accountAddress = "act_aws_account_deployment.this"
	orgAddress     = "act_aws_organization_deployment.this"
	testOrg        = "o-abcdefghij"
	testRoot       = "r-ab12"
	testOU         = "ou-ab12-abcdefgh"
	otherOU        = "ou-ab12-ijklmnop"
)

func accountConfig(body string) string {
	return accountConfigWithRole("data.act_aws_onboarding_parameters.this.role_arn", body)
}

func accountConfigWithRole(role, body string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_aws_onboarding_parameters" "this" {
  account_id = %q
}

resource "act_aws_account_deployment" "this" {
  deployment_id           = data.act_aws_onboarding_parameters.this.deployment_id
  account_id              = %q
  role_arn                = %s
  external_id_key_version = data.act_aws_onboarding_parameters.this.external_id_key_version
%s
}
`, testAccount, testAccount, role, body)
}

func roleArn(account string) string {
	return "arn:aws:iam::" + account + ":role/act"
}

func countRequests(s *fakeapi.Servers, method, suffix string) int {
	n := 0
	for _, req := range s.Recorder().Requests() {
		if req.Origin == fakeapi.OriginAPI && req.Method == method && strings.HasSuffix(req.Path, suffix) {
			n++
		}
	}
	return n
}

func TestAwsAccountDeploymentLifecycle(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	id := s.DeploymentID("aws:account:"+testAccount, "")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: accountConfig(""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("name"), knownvalue.StringExact("aws-"+testAccount)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("deployment_method"), knownvalue.StringExact("terraform")),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("external_id_source"), knownvalue.StringExact("derived")),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("reverify_on_failure"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("tags"), knownvalue.Null()),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("allowed_regions"), knownvalue.Null()),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("disabled_capabilities"), knownvalue.SetSizeExact(0)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("console_url"), knownvalue.StringExact(fakeapi.ConsoleOrigin+"/settings/deployments/"+id)),
					statecheck.ExpectKnownValue("data.act_aws_onboarding_parameters.this", tfjsonpath.New("existing_deployment"), knownvalue.Null()),
				},
				Check: resource.TestCheckResourceAttrPair(accountAddress, "external_id", "data.act_aws_onboarding_parameters.this", "external_id"),
			},
			{
				Config:   accountConfig(""),
				PlanOnly: true,
			},
			{
				Config: accountConfig(`
  name                  = "production"
  tags                  = { team = "platform" }
  allowed_regions       = ["us-east-1", "eu-west-1"]
  disabled_capabilities = ["eks_cluster_access"]
`),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("name"), knownvalue.StringExact("production")),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("allowed_regions"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("disabled_capabilities"), knownvalue.SetExact([]knownvalue.Check{knownvalue.StringExact("eks_cluster_access")})),
				},
			},
			{
				Config: accountConfig(`
  name = "production"
`),
				Check: func(*terraform.State) error {
					item, ok := s.AwsDeployment(id)
					if !ok {
						return fmt.Errorf("deployment %s is missing from the fake", id)
					}
					if item.AllowedRegions != nil || len(item.Tags) != 0 {
						return fmt.Errorf("allowed regions %v and tags %v were not cleared", item.AllowedRegions, item.Tags)
					}
					return nil
				},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("tags"), knownvalue.Null()),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("allowed_regions"), knownvalue.Null()),
				},
			},
			{
				PreConfig: func() {
					if !s.FailDeploymentOutOfBand(id, "ROLE_NOT_FOUND", "The role does not exist") {
						t.Fatal("the deployment is missing from the fake")
					}
				},
				Config: accountConfig(`
  name = "production"
`),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionUpdate),
					plancheck.ExpectUnknownValue(accountAddress, tfjsonpath.New("status")),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("error_code"), knownvalue.Null()),
				},
				Check: func(*terraform.State) error {
					if n := countRequests(s, "POST", id+"/verify"); n != 1 {
						return fmt.Errorf("verify was called %d times, want 1", n)
					}
					return nil
				},
			},
			{
				ResourceName:            accountAddress,
				ImportState:             true,
				ImportStateId:           testAccount,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				ResourceName:            accountAddress,
				ImportState:             true,
				ImportStateId:           id,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				PreConfig: func() { s.DeleteDeploymentOutOfBand(id) },
				Config: accountConfig(`
  name = "production"
`),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionCreate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
				},
			},
		},
	})
}

func TestAwsAccountDeploymentWaitsForTheRoleToPropagate(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	propagating := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassPropagate, CloudErrorCode: "AccessDenied"}
	s.QueueVerificationFailures(roleArn(testAccount), propagating, propagating)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: accountConfigWithRole(fmt.Sprintf("%q", roleArn(testAccount)), ""),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
			},
			Check: func(*terraform.State) error {
				if n := countRequests(s, "POST", "/v1/deployments/aws"); n != 3 {
					return fmt.Errorf("create was called %d times, want 3", n)
				}
				return nil
			},
		}},
	})
}

func TestAwsAccountDeploymentStopsOnARepeatedDeterministicFailure(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	notEnforced := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassDetermined, CloudErrorCode: "EXTERNAL_ID_NOT_ENFORCED", Hint: "Require the external ID in the trust policy."}
	s.QueueVerificationFailures(roleArn(testAccount), notEnforced, notEnforced, notEnforced)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:      accountConfigWithRole(fmt.Sprintf("%q", roleArn(testAccount)), ""),
				ExpectError: regexp.MustCompile(`(?s)EXTERNAL_ID_NOT_ENFORCED.*Require the external ID.*same answer 2 times`),
			},
			{
				PreConfig: func() {
					if n := countRequests(s, "POST", "/v1/deployments/aws"); n != 2 {
						t.Fatalf("create was called %d times, want 2", n)
					}
					if _, ok := s.AwsDeployment(s.DeploymentID("aws:account:"+testAccount, "")); ok {
						t.Fatal("a failed create stored the deployment")
					}
				},
				Config:             accountConfigWithRole(fmt.Sprintf("%q", roleArn(testAccount)), ""),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAwsAccountDeploymentRejectsARoleInAnotherAccount(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      accountConfigWithRole(fmt.Sprintf("%q", roleArn(otherAccount)), ""),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`role_arn is in account 222222222222, but account_id is 111111111111`),
		}},
	})
}

func TestAwsAccountDeploymentPrintsAnImportBlockWhenOneExists(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	existing := s.SeedLegacyAwsAccountDeployment(testAccount, roleArn(testAccount), "legacy-external-id")
	config := requiredProviders + fmt.Sprintf(`
provider "act" {}

resource "act_aws_account_deployment" "this" {
  deployment_id = %q
  account_id    = %q
  role_arn      = %q
}
`, s.DeploymentID("aws:account:"+testAccount, ""), testAccount, roleArn(testAccount))

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      config,
			ExpectError: regexp.MustCompile(`(?s)import \{\s+to = act_aws_account_deployment.<name>\s+id = "` + existing + `"`),
		}},
	})
}

func TestAwsAccountDeploymentRotatesALegacyExternalID(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	id := s.SeedLegacyAwsAccountDeployment(testAccount, roleArn(testAccount), "legacy-external-id")
	config := func(source string) string {
		return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_aws_onboarding_parameters" "this" {
  account_id = %q
}

import {
  to = act_aws_account_deployment.this
  id = %q
}

resource "act_aws_account_deployment" "this" {
  deployment_id      = data.act_aws_onboarding_parameters.this.deployment_id
  account_id         = %q
  role_arn           = %q
  deployment_method  = "cloudformation"
  external_id_source = %q
}
`, testAccount, testAccount, testAccount, roleArn(testAccount), source)
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: config("legacy"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("external_id"), knownvalue.StringExact("legacy-external-id")),
					statecheck.ExpectKnownValue("data.act_aws_onboarding_parameters.this", tfjsonpath.New("existing_deployment").AtMapKey("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue("data.act_aws_onboarding_parameters.this", tfjsonpath.New("existing_deployment").AtMapKey("created_via"), knownvalue.StringExact("ui")),
				},
			},
			{
				Config: config("derived"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(accountAddress, plancheck.ResourceActionUpdate),
					plancheck.ExpectUnknownValue(accountAddress, tfjsonpath.New("external_id")),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(accountAddress, tfjsonpath.New("external_id_source"), knownvalue.StringExact("derived")),
				},
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttrPair(accountAddress, "external_id", "data.act_aws_onboarding_parameters.this", "target_external_id"),
					func(*terraform.State) error {
						if n := countRequests(s, "POST", id+"/rotate-external-id"); n != 1 {
							return fmt.Errorf("rotate was called %d times, want 1", n)
						}
						return nil
					},
				),
			},
			{
				Config:      config("legacy"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`The external ID cannot go back to legacy`),
			},
		},
	})
}

func orgConfig(scope, extra string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_aws_onboarding_parameters" "this" {
  organization_id = %q
}

resource "act_aws_organization_deployment" "this" {
  deployment_id   = data.act_aws_onboarding_parameters.this.deployment_id
  organization_id = %q
  role_arn        = %q
%s
%s
}
`, testOrg, testOrg, roleArn(otherAccount), scope, extra)
}

func TestAwsOrganizationDeploymentLifecycle(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	id := s.DeploymentID("aws:organization:"+testOrg, "")
	root := `  root_id = "` + testRoot + `"`
	ous := fmt.Sprintf("  organizational_unit_ids = [%q, %q]", testOU, otherOU)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: orgConfig(root, `  excluded_account_ids = ["333333333333"]`),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("member_role_name"), knownvalue.StringExact("ActSecurityRole-"+id)),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("member_role_path"), knownvalue.StringExact("/")),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("management_account_id"), knownvalue.StringExact(otherAccount)),
					statecheck.ExpectKnownValue("data.act_aws_onboarding_parameters.this", tfjsonpath.New("role_arn"), knownvalue.Null()),
				},
			},
			{
				Config:   orgConfig(root, `  excluded_account_ids = ["333333333333"]`),
				PlanOnly: true,
			},
			{
				Config: orgConfig(ous, ""),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(orgAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("root_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("organizational_unit_ids"), knownvalue.SetSizeExact(2)),
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("excluded_account_ids"), knownvalue.Null()),
				},
			},
			{
				ResourceName:            orgAddress,
				ImportState:             true,
				ImportStateId:           testOrg,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				Config:      orgConfig(ous, ""),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`deletion protection`),
			},
			{
				Config:      strings.Replace(orgConfig(ous, ""), "organization_id = \""+testOrg+"\"", "organization_id = \"o-zyxwvutsrq\"", 1),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`This change replaces`),
			},
			{
				Config: orgConfig(ous, "  deletion_protection = false"),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(orgAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAwsOrganizationDeploymentImportsByRoot(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	provider.FastVerification(t)
	root := `  root_id = "` + testRoot + `"`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: orgConfig(root, "  deletion_protection = false")},
			{
				ResourceName:            orgAddress,
				ImportState:             true,
				ImportStateId:           testRoot,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				ResourceName:  orgAddress,
				ImportState:   true,
				ImportStateId: testAccount,
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
		},
	})
}

func TestAwsOrganizationDeploymentLimitsTheOUList(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	ids := make([]string, 0, 60)
	for i := range 60 {
		ids = append(ids, fmt.Sprintf("%q", fmt.Sprintf("ou-ab12-%08d", i)))
	}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      orgConfig("  organizational_unit_ids = ["+strings.Join(ids, ", ")+"]", ""),
			PlanOnly:    true,
			ExpectError: regexp.MustCompile(`(?s)The 60 organizational unit IDs take 1019 characters.*root_id`),
		}},
	})
}
