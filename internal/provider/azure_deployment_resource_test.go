//go:build actinternal

package provider_test

import (
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
	"github.com/act-security/terraform-provider-act/internal/fakeapi/gen"
	"github.com/act-security/terraform-provider-act/internal/provider"
)

const (
	azureAddress           = "act_azure_deployment.this"
	azureOnboarding        = "data.act_azure_onboarding_parameters.this"
	testDirectory          = "00000000-0000-4000-8000-0000000000d1"
	testSubscription       = "11111111-1111-4111-8111-111111111111"
	otherSubscription      = "22222222-2222-4222-8222-222222222222"
	testManagementGroup    = "mg-platform"
	otherManagementGroup   = "mg-sandbox"
	testServicePrincipal   = "33333333-3333-4333-8333-333333333333"
	otherServicePrincipal  = "44444444-4444-4444-8444-444444444444"
	subscriptionTarget     = `subscription_id = "` + testSubscription + `"`
	managementGroupTarget  = `management_group_id = "` + testManagementGroup + `"`
	azureRoleNotAssigned   = "RoleAssignmentNotFound"
	azurePropagationDenied = "AuthorizationFailed"
)

type azureCase struct {
	target    string
	principal string
	body      string
	extra     string
}

func (c azureCase) config() string {
	principal := c.principal
	if principal == "" {
		principal = testServicePrincipal
	}
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_azure_onboarding_parameters" "this" {
  directory_id = %q
  %s
}

resource "act_azure_deployment" "this" {
  deployment_id        = data.act_azure_onboarding_parameters.this.deployment_id
  azure_tenant_id      = data.act_azure_onboarding_parameters.this.azure_tenant_id
  service_principal_id = %q
  %s
%s
}
%s
`, testDirectory, c.target, principal, c.target, c.body, c.extra)
}

func startAzureFake(t *testing.T, opts ...fakeapi.Option) *fakeapi.Servers {
	t.Helper()
	s := fakeapi.Start(t, opts...)
	s.Setenv(t)
	provider.FastVerification(t)
	return s
}

func requestCount(s *fakeapi.Servers, method, suffix string, want int) resource.TestCheckFunc {
	return func(*terraform.State) error {
		if n := countRequests(s, method, suffix); n != want {
			return fmt.Errorf("%s %s was sent %d times, want %d", method, suffix, n, want)
		}
		return nil
	}
}

func TestAzureSubscriptionDeploymentLifecycle(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)
	renamed := azureCase{target: subscriptionTarget, body: `
  name             = "production"
  tags             = { team = "platform" }
  include_entra_id = true
`}
	lookup := renamed
	lookup.extra = `
data "act_deployment" "by_target" {
  target = act_azure_deployment.this.subscription_id
  cloud  = "azure"
}
`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: azureCase{target: subscriptionTarget}.config(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("consent_url"), knownvalue.Null()),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("name"), knownvalue.StringExact("azure-"+testSubscription)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("azure_tenant_id"), knownvalue.StringExact(testDirectory)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("management_group_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("deployment_method"), knownvalue.StringExact("terraform")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("include_entra_id"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("reverify_on_failure"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("tags"), knownvalue.Null()),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("created_via"), knownvalue.StringExact("api")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("console_url"), knownvalue.StringExact(fakeapi.ConsoleOrigin+"/settings/deployments/"+id)),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("existing_deployment"), knownvalue.Null()),
				},
			},
			{
				Config:   azureCase{target: subscriptionTarget}.config(),
				PlanOnly: true,
			},
			{
				Config: renamed.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("name"), knownvalue.StringExact("production")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("tags").AtMapKey("team"), knownvalue.StringExact("platform")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("include_entra_id"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("existing_deployment").AtMapKey("id"), knownvalue.StringExact(id)),
				},
			},
			{
				PreConfig: func() {
					if !s.FailDeploymentOutOfBand(fakeapi.DeploymentFailure{DeploymentID: id, Code: azureRoleNotAssigned, Message: "The custom role is not assigned"}) {
						t.Fatal("the deployment is missing from the fake")
					}
				},
				Config: renamed.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionUpdate),
					plancheck.ExpectUnknownValue(azureAddress, tfjsonpath.New("status")),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("error_code"), knownvalue.Null()),
				},
				Check: requestCount(s, "POST", id+"/verify", 1),
			},
			{
				Config: lookup.config(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue("data.act_deployment.by_target", tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue("data.act_deployment.by_target", tfjsonpath.New("scope"), knownvalue.StringExact("subscription")),
				},
			},
			{
				ResourceName:            azureAddress,
				ImportState:             true,
				ImportStateId:           "subscription/" + testSubscription,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				ResourceName:            azureAddress,
				ImportState:             true,
				ImportStateId:           id,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				PreConfig: func() { s.DeleteDeploymentOutOfBand(id) },
				Config:    renamed.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionCreate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
				},
			},
		},
	})
}

func TestAzureDeploymentSucceedsPendingConsentAndTurnsActiveAfterApproval(t *testing.T) {
	s := startAzureFake(t)
	id := s.AzureSubscriptionDeploymentID(testSubscription)
	config := azureCase{target: subscriptionTarget}.config()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: config,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("pending_consent")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("consent_url"), knownvalue.StringExact(fakeapi.AzureAdminConsentURL(testDirectory))),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("tenant_consented"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("act_service_principal_id"), knownvalue.Null()),
				},
			},
			{
				Config:   config,
				PlanOnly: true,
			},
			{
				PreConfig: func() { s.GrantAzureConsent(testDirectory) },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("consent_url"), knownvalue.Null()),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("tenant_consented"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("act_service_principal_id"), knownvalue.StringExact(s.AzureServicePrincipalID(testDirectory))),
				},
				Check: resource.ComposeTestCheckFunc(
					requestCount(s, "POST", id+"/verify", 0),
					requestCount(s, "PATCH", id, 0),
				),
			},
		},
	})
}

func TestAzureManagementGroupDeploymentIsProtectedByDefault(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureManagementGroupDeploymentID(testManagementGroup)
	group := azureCase{target: managementGroupTarget}
	otherGroup := azureCase{target: `management_group_id = "` + otherManagementGroup + `"`}
	cli := azureCase{target: managementGroupTarget, body: `  deployment_method = "cli"`}
	unprotected := azureCase{target: managementGroupTarget, body: "  deletion_protection = false"}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: group.config(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("subscription_id"), knownvalue.Null()),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
				},
			},
			{
				Config:   group.config(),
				PlanOnly: true,
			},
			{
				ResourceName:            azureAddress,
				ImportState:             true,
				ImportStateId:           "management-group/" + testManagementGroup,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"timeouts"},
			},
			{
				ResourceName:  azureAddress,
				ImportState:   true,
				ImportStateId: "tenant/" + testDirectory,
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
			{
				ResourceName:  azureAddress,
				ImportState:   true,
				ImportStateId: "subscription/" + otherSubscription,
				ExpectError:   regexp.MustCompile(`This tenant has no Azure subscription deployment for\s+` + otherSubscription),
			},
			{
				Config:      group.config(),
				Destroy:     true,
				ExpectError: regexp.MustCompile(`(?s)Act refuses to delete ` + id + ` while\s+deletion_protection is true`),
			},
			{
				Config:      otherGroup.config(),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`This change replaces`),
			},
			{
				Config:      cli.config(),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`This change replaces`),
			},
			{
				Config: unprotected.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("deletion_protection"), knownvalue.Bool(false)),
				},
			},
		},
	})
}

func TestAzureDeploymentReplacesItWhenTheTargetOrMethodChanges(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	other := `subscription_id = "` + otherSubscription + `"`

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: azureCase{target: subscriptionTarget}.config()},
			{
				Config: azureCase{target: subscriptionTarget, body: `  deployment_method = "manual"`}.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("deployment_method"), knownvalue.StringExact("manual")),
				},
			},
			{
				Config: azureCase{target: other, body: `  deployment_method = "manual"`}.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionDestroyBeforeCreate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(s.AzureSubscriptionDeploymentID(otherSubscription))),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("subscription_id"), knownvalue.StringExact(otherSubscription)),
				},
				Check: func(*terraform.State) error {
					if _, ok := s.AzureDeployment(s.AzureSubscriptionDeploymentID(testSubscription)); ok {
						return fmt.Errorf("the replaced deployment is still in the fake")
					}
					return nil
				},
			},
		},
	})
}

func TestAzureDeploymentSwapsTheServicePrincipalInPlace(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: azureCase{target: subscriptionTarget}.config()},
			{
				Config: azureCase{target: subscriptionTarget, principal: otherServicePrincipal}.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(azureAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("service_principal_id"), knownvalue.StringExact(otherServicePrincipal)),
				},
			},
		},
	})
}

func TestAzureDeploymentWaitsForTheRoleAssignmentsToPropagate(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	propagating := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassPropagate, CloudErrorCode: azurePropagationDenied}
	s.QueueVerificationFailures(testServicePrincipal, propagating, propagating)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: azureCase{target: subscriptionTarget}.config(),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("active")),
			},
			Check: requestCount(s, "POST", "/v1/deployments/azure", 3),
		}},
	})
}

func TestAzureDeploymentStopsOnARepeatedDeterministicFailure(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	missing := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassDetermined, CloudErrorCode: azureRoleNotAssigned, Hint: "Assign the custom role to the service principal at the subscription."}
	s.QueueVerificationFailures(testServicePrincipal, missing, missing, missing)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:      azureCase{target: subscriptionTarget}.config(),
				ExpectError: regexp.MustCompile(`(?s)service_principal_id.*Act could not use the service principal:\s+RoleAssignmentNotFound.*same\s+answer 2 times.*Azure\s+side.*Nothing\s+was\s+stored`),
			},
			{
				PreConfig: func() {
					if _, ok := s.AzureDeployment(s.AzureSubscriptionDeploymentID(testSubscription)); ok {
						t.Fatal("a failed create stored the deployment")
					}
				},
				Config:             azureCase{target: subscriptionTarget}.config(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
		},
	})
}

func TestAzureDeploymentLeavesAFailureAloneWhenReverifyIsOff(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)
	config := azureCase{target: subscriptionTarget, body: "  reverify_on_failure = false"}.config()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: config},
			{
				PreConfig: func() {
					s.FailDeploymentOutOfBand(fakeapi.DeploymentFailure{DeploymentID: id, Code: azureRoleNotAssigned, Message: "The custom role is not assigned"})
				},
				Config: config,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectEmptyPlan(),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("status"), knownvalue.StringExact("failed")),
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("error_code"), knownvalue.StringExact(azureRoleNotAssigned)),
				},
				Check: requestCount(s, "POST", id+"/verify", 0),
			},
		},
	})
}

func TestAzureDeploymentRetriesOnceWhenOnlyTheETagMoved(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: azureCase{target: subscriptionTarget}.config()},
			{
				PreConfig: func() { s.ChangeAzureDeploymentBeforeNextPatch(id, func(*gen.AzureDeployment) {}) },
				Config:    azureCase{target: subscriptionTarget, body: `  name = "renamed"`}.config(),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(azureAddress, tfjsonpath.New("name"), knownvalue.StringExact("renamed")),
				},
				Check: requestCount(s, "PATCH", id, 2),
			},
		},
	})
}

func TestAzureDeploymentStopsWhenSomeoneChangedItDuringTheApply(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		CheckDestroy:             staleDeleteRetriedOnce(s),
		Steps: []resource.TestStep{
			{Config: azureCase{target: subscriptionTarget}.config()},
			{
				PreConfig: func() {
					s.ChangeAzureDeploymentBeforeNextPatch(id, func(item *gen.AzureDeployment) { item.Name = "set-in-the-console" })
				},
				Config:      azureCase{target: subscriptionTarget, body: `  name = "renamed"`}.config(),
				ExpectError: regexp.MustCompile(`Someone changed deployment ` + id),
			},
		},
	})
}

func staleDeleteRetriedOnce(s *fakeapi.Servers) resource.TestCheckFunc {
	return func(*terraform.State) error {
		statuses := []int{}
		for _, req := range s.Recorder().Requests() {
			if req.Origin == fakeapi.OriginAPI && req.Method == http.MethodDelete {
				statuses = append(statuses, req.Status)
			}
		}
		if !slices.Equal(statuses, []int{http.StatusPreconditionFailed, http.StatusOK}) {
			return fmt.Errorf("delete answered %v, want a 412 for the stale ETag and then 200", statuses)
		}
		return nil
	}
}

func TestAzureDeploymentPrintsAnImportBlockWhenOneExists(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)
	second := azureCase{target: subscriptionTarget, extra: fmt.Sprintf(`
resource "act_azure_deployment" "again" {
  deployment_id        = %q
  azure_tenant_id      = %q
  service_principal_id = %q
  subscription_id      = %q
  depends_on           = [act_azure_deployment.this]
}
`, id, testDirectory, testServicePrincipal, testSubscription)}

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      second.config(),
			ExpectError: regexp.MustCompile(`(?s)import \{\s+to = act_azure_deployment.<name>\s+id = "` + id + `"`),
		}},
	})
}

func TestAReadOnlyKeyCannotApplyAnAzureDeployment(t *testing.T) {
	s := startAzureFake(t, fakeapi.WithKey(fakeapi.TerraformDeploymentsPlanKey))
	s.GrantAzureConsent(testDirectory)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:             azureCase{target: subscriptionTarget}.config(),
				PlanOnly:           true,
				ExpectNonEmptyPlan: true,
			},
			{
				Config:      azureCase{target: subscriptionTarget}.config(),
				ExpectError: regexp.MustCompile(`(?s)This apply creates act_azure_deployment, which needs the\s+deployments:write\s+scope.*Nothing\s+was\s+sent\s+to\s+Act`),
			},
		},
	})

	if n := publicAPIWrites(s); n != 0 {
		t.Fatalf("the provider sent %d write requests with a read-only key, want none", n)
	}
}

func azureOnboardingConfig(target string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

data "act_azure_onboarding_parameters" "this" {
  directory_id = %q
  %s
}
`, testDirectory, target)
}

func TestAzureOnboardingParametersForASubscription(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: azureOnboardingConfig(subscriptionTarget),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("deployment_id"), knownvalue.StringExact(id)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("existing_deployment"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("azure_tenant_id"), knownvalue.StringExact(testDirectory)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("tenant_consented"), knownvalue.Bool(true)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("admin_consent_url"), knownvalue.StringExact(fakeapi.AzureAdminConsentURL(testDirectory))),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("act_app_client_id"), knownvalue.StringExact(fakeapi.ActAzureAppClientID)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("act_service_principal_id"), knownvalue.StringExact(s.AzureServicePrincipalID(testDirectory))),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("custom_role_name"), knownvalue.StringExact("ActSecurityReader-"+id)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("custom_role_actions"), knownvalue.ListSizeExact(2)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("binding_marker"), knownvalue.StringExact("act-deployment:"+id)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("required_builtin_role_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(fakeapi.AzureReaderRoleID)})),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("required_graph_app_role_ids"), knownvalue.ListExact([]knownvalue.Check{knownvalue.StringExact(fakeapi.AzureDirectoryReadRoleID)})),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_source"), knownvalue.StringExact(fakeapi.AzureModuleSource)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_version"), knownvalue.StringExact(fakeapi.ModuleVersion)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_versions").AtSliceIndex(0).AtMapKey("version"), knownvalue.StringExact(fakeapi.ModuleVersion)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("deployment_version"), knownvalue.NotNull()),
			},
		}},
	})
}

func TestAzureOnboardingParametersBeforeModulesArePublished(t *testing.T) {
	s := startAzureFake(t)
	s.UnpublishModules()

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: azureOnboardingConfig(managementGroupTarget),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("deployment_id"), knownvalue.StringExact(s.AzureManagementGroupDeploymentID(testManagementGroup))),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("tenant_consented"), knownvalue.Bool(false)),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("act_service_principal_id"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_source"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_sha256"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("permissions_hash"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("deployment_version"), knownvalue.Null()),
				statecheck.ExpectKnownValue(azureOnboarding, tfjsonpath.New("module_versions"), knownvalue.Null()),
			},
		}},
	})
}

func TestAzureOnboardingParametersNeedsOneTarget(t *testing.T) {
	startAzureFake(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:      azureOnboardingConfig(subscriptionTarget + "\n  " + managementGroupTarget),
				ExpectError: regexp.MustCompile(`Invalid Attribute Combination`),
			},
			{
				Config:      azureOnboardingConfig(""),
				ExpectError: regexp.MustCompile(`Missing Attribute Configuration`),
			},
		},
	})
}
