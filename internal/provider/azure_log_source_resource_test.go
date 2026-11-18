//go:build actinternal

package provider_test

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/knownvalue"
	"github.com/hashicorp/terraform-plugin-testing/plancheck"
	"github.com/hashicorp/terraform-plugin-testing/statecheck"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
	"github.com/hashicorp/terraform-plugin-testing/tfjsonpath"

	"github.com/act-security/terraform-provider-act/internal/fakeapi"
)

const (
	logSourceAddress     = "act_azure_log_source.this"
	eventsSubscription   = "55555555-5555-4555-8555-555555555555"
	otherEventsSub       = "66666666-6666-4666-8666-666666666666"
	eventHubAccessDenied = "EventHubAccessDenied"
)

func logSourceConfig(eventsSubscriptionID, streams string) string {
	return azureCase{target: subscriptionTarget, extra: fmt.Sprintf(`
resource "act_azure_log_source" "this" {
  deployment_id          = act_azure_deployment.this.id
  events_subscription_id = %q
%s
}
`, eventsSubscriptionID, streams)}.config()
}

func eventHub(namespace, hub, dataType string, enabled bool) knownvalue.Check {
	return knownvalue.ObjectExact(map[string]knownvalue.Check{
		"namespace": knownvalue.StringExact(namespace),
		"event_hub": knownvalue.StringExact(hub),
		"data_type": knownvalue.StringExact(dataType),
		"enabled":   knownvalue.Bool(enabled),
	})
}

func TestAzureLogSourceLifecycle(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	id := s.AzureSubscriptionDeploymentID(testSubscription)
	namespace := fakeapi.EventHubNamespace(eventsSubscription)
	activityOnly := logSourceConfig(eventsSubscription, "  activity_logs = true")
	entraOnly := logSourceConfig(eventsSubscription, "  entra_id_logs = true")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: activityOnly,
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("id"), knownvalue.StringExact(id)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("activity_logs"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("entra_id_logs"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("events_subscription_id"), knownvalue.StringExact(eventsSubscription)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("event_hubs"), knownvalue.ListExact([]knownvalue.Check{
						eventHub(namespace, "act-activity-logs", "activity_logs", true),
					})),
				},
			},
			{
				Config:   activityOnly,
				PlanOnly: true,
			},
			{
				Config: entraOnly,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(logSourceAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("activity_logs"), knownvalue.Bool(false)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("entra_id_logs"), knownvalue.Bool(true)),
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("event_hubs"), knownvalue.ListExact([]knownvalue.Check{
						eventHub(namespace, "act-activity-logs", "activity_logs", false),
						eventHub(namespace, "act-entra-id-logs", "entra_id_logs", true),
					})),
				},
			},
			{
				ResourceName:            logSourceAddress,
				ImportState:             true,
				ImportStateId:           id,
				ImportStateVerify:       true,
				ImportStateVerifyIgnore: []string{"events_subscription_id", "timeouts"},
			},
			{
				ResourceName:  logSourceAddress,
				ImportState:   true,
				ImportStateId: "subscription/" + testSubscription,
				ExpectError:   regexp.MustCompile(`Invalid import ID`),
			},
			{
				Config: logSourceConfig(otherEventsSub, "  entra_id_logs = true"),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(logSourceAddress, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("event_hubs").AtSliceIndex(1).AtMapKey("namespace"), knownvalue.StringExact(fakeapi.EventHubNamespace(otherEventsSub))),
				},
			},
			{
				Config: azureCase{target: subscriptionTarget}.config(),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(logSourceAddress, plancheck.ResourceActionDestroy),
				}},
				Check: resource.ComposeTestCheckFunc(
					requestCount(s, "DELETE", id+"/log-source", 1),
					func(*terraform.State) error {
						if _, ok := s.AzureLogSource(id); ok {
							return fmt.Errorf("the log source of %s is still in the fake", id)
						}
						return nil
					},
				),
			},
		},
	})
}

func TestAzureLogSourceComesBackWhenItWasRemovedInAct(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	config := logSourceConfig(eventsSubscription, "  activity_logs = true")

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{Config: config},
			{
				PreConfig: func() { s.DeleteAzureLogSourceOutOfBand(s.AzureSubscriptionDeploymentID(testSubscription)) },
				Config:    config,
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(logSourceAddress, plancheck.ResourceActionCreate),
				}},
			},
		},
	})
}

func TestAzureLogSourceWaitsForTheEventHubAccessToPropagate(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	propagating := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassPropagate, CloudErrorCode: eventHubAccessDenied}
	s.QueueVerificationFailures(eventsSubscription, propagating, propagating)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config: logSourceConfig(eventsSubscription, "  activity_logs = true\n  entra_id_logs = true"),
			ConfigStateChecks: []statecheck.StateCheck{
				statecheck.ExpectKnownValue(logSourceAddress, tfjsonpath.New("event_hubs"), knownvalue.ListSizeExact(2)),
			},
			Check: requestCount(s, "PUT", id+"/log-source", 3),
		}},
	})
}

func TestAzureLogSourceStopsOnARepeatedDeterministicFailure(t *testing.T) {
	s := startAzureFake(t)
	s.GrantAzureConsent(testDirectory)
	denied := fakeapi.VerificationFailure{RetryClass: fakeapi.RetryClassDetermined, CloudErrorCode: eventHubAccessDenied, Hint: "Grant Act's service principal the Azure Event Hubs Data Receiver role on the namespace."}
	s.QueueVerificationFailures(eventsSubscription, denied, denied, denied)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      logSourceConfig(eventsSubscription, "  activity_logs = true"),
			ExpectError: regexp.MustCompile(`(?s)events_subscription_id.*Act could not use the Event\s+Hubs:\s+EventHubAccessDenied.*same\s+answer 2 times`),
		}},
	})
}

func TestAzureLogSourceNeedsAnActiveDeployment(t *testing.T) {
	s := startAzureFake(t)
	id := s.AzureSubscriptionDeploymentID(testSubscription)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{{
			Config:      logSourceConfig(eventsSubscription, "  activity_logs = true"),
			ExpectError: regexp.MustCompile(`(?s)Act collects logs only through an active deployment, and\s+deployment\s+` + id + `\s+is not active: The deployment is\s+pending_consent\.`),
		}},
	})
}

func TestAzureLogSourceNeedsAStream(t *testing.T) {
	startAzureFake(t)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config:      logSourceConfig(eventsSubscription, "  activity_logs = false"),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`No log stream to collect`),
			},
			{
				Config:      logSourceConfig(eventsSubscription, ""),
				PlanOnly:    true,
				ExpectError: regexp.MustCompile(`No log stream to collect`),
			},
		},
	})
}
