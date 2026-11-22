//go:build actinternal

package provider_test

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
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

type pastedKeyKind struct {
	resourceType string
	importID     string
	secretAttr   string
	first        map[string]string
	changed      map[string]string
	wantConfig   map[string]string
}

var pastedKeyKinds = []pastedKeyKind{
	{
		resourceType: "act_cortex_cloud_integration",
		importID:     "cortex-cloud",
		secretAttr:   "api_key",
		first: map[string]string{
			"api_url":        "https://api-acme.xdr.us.paloaltonetworks.com",
			"api_key_id":     "7",
			"security_level": "standard",
		},
		changed: map[string]string{
			"api_url":        "https://api-acme.xdr.us.paloaltonetworks.com",
			"api_key_id":     "8",
			"security_level": "advanced",
		},
		wantConfig: map[string]string{
			"apiUrl":        "https://api-acme.xdr.us.paloaltonetworks.com",
			"apiKeyId":      "8",
			"securityLevel": "advanced",
		},
	},
}

func (k pastedKeyKind) address() string { return k.resourceType + ".this" }

func (k pastedKeyKind) writeOnly(config map[string]string, secret string, version int) string {
	body := ""
	for _, attr := range slices.Sorted(maps.Keys(config)) {
		body += fmt.Sprintf("  %s = %q\n", attr, config[attr])
	}
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

resource %q "this" {
%s  %s_wo         = %q
  %s_wo_version = %d
}
`, k.resourceType, body, k.secretAttr, secret, k.secretAttr, version)
}

func TestPastedKeyIntegrationsLifecycle(t *testing.T) {
	for _, kind := range pastedKeyKinds {
		t.Run(kind.resourceType, func(t *testing.T) {
			s := fakeapi.Start(t)
			s.Setenv(t)
			var id string

			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: factories(),
				TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
				Steps: []resource.TestStep{
					{
						Config: kind.writeOnly(kind.first, "first-secret", 1),
						ConfigStateChecks: []statecheck.StateCheck{
							statecheck.ExpectKnownValue(kind.address(), tfjsonpath.New("status"), knownvalue.StringExact("connected")),
							statecheck.ExpectKnownValue(kind.address(), tfjsonpath.New(kind.secretAttr), knownvalue.Null()),
							statecheck.ExpectKnownValue(kind.address(), tfjsonpath.New(kind.secretAttr+"_updated_at"), knownvalue.NotNull()),
						},
						Check: resource.ComposeTestCheckFunc(noStoredValue("first-secret"), captureID(kind.address(), &id), func(*terraform.State) error {
							if got, _ := s.IntegrationSecret(id); got != "first-secret" {
								return fmt.Errorf("Act holds %q, want the configured secret", got)
							}
							return nil
						}),
					},
					{
						Config:   kind.writeOnly(kind.first, "first-secret", 1),
						PlanOnly: true,
					},
					{
						Config: kind.writeOnly(kind.changed, "second-secret", 1),
						ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
							plancheck.ExpectResourceAction(kind.address(), plancheck.ResourceActionUpdate),
						}},
						Check: resource.ComposeTestCheckFunc(noStoredValue("second-secret"), func(st *terraform.State) error {
							if st.RootModule().Resources[kind.address()].Primary.ID != id {
								return fmt.Errorf("a settings change replaced the integration")
							}
							if got, _ := s.IntegrationSecret(id); got != "second-secret" {
								return fmt.Errorf("Act holds %q, want the secret sent with the changed settings", got)
							}
							if got, _ := s.IntegrationConfig(id); !maps.Equal(got, kind.wantConfig) {
								return fmt.Errorf("Act holds settings %v, want %v", got, kind.wantConfig)
							}
							return nil
						}),
					},
					{
						ResourceName:            kind.address(),
						ImportState:             true,
						ImportStateId:           kind.importID,
						ImportStateVerify:       true,
						ImportStateVerifyIgnore: []string{kind.secretAttr + "_wo_version"},
					},
				},
			})
		})
	}
}

func splunkWithTLS(tls string) string {
	return requiredProviders + fmt.Sprintf(`
provider "act" {}

resource "act_splunk_integration" "this" {
  hec_url   = "https://http-inputs-acme.splunkcloud.com"
  hec_token = "hec-token"
%s}
`, tls)
}

const splunkCA = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"

func TestSplunkIntegrationSendsTLSPinningOnlyWhenConfigured(t *testing.T) {
	s := fakeapi.Start(t)
	s.Setenv(t)
	address := "act_splunk_integration.this"
	var id string
	pinned := fmt.Sprintf("  tls_ca_certificate = %q\n  tls_hostname_check = \"skip\"\n", splunkCA)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: factories(),
		Steps: []resource.TestStep{
			{
				Config: splunkWithTLS(""),
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("tls_ca_certificate"), knownvalue.Null()),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("tls_hostname_check"), knownvalue.Null()),
				},
				Check: resource.ComposeTestCheckFunc(captureID(address, &id), func(*terraform.State) error {
					config, _ := s.IntegrationConfig(id)
					if _, sent := config["tlsCaCertificate"]; sent {
						return fmt.Errorf("the provider sent tlsCaCertificate though it is not configured")
					}
					if _, sent := config["tlsHostnameCheck"]; sent {
						return fmt.Errorf("the provider sent tlsHostnameCheck though it is not configured")
					}
					return nil
				}),
			},
			{
				Config: splunkWithTLS(pinned),
				ConfigPlanChecks: resource.ConfigPlanChecks{PreApply: []plancheck.PlanCheck{
					plancheck.ExpectResourceAction(address, plancheck.ResourceActionUpdate),
				}},
				ConfigStateChecks: []statecheck.StateCheck{
					statecheck.ExpectKnownValue(address, tfjsonpath.New("tls_ca_certificate"), knownvalue.StringExact(splunkCA)),
					statecheck.ExpectKnownValue(address, tfjsonpath.New("tls_hostname_check"), knownvalue.StringExact("skip")),
				},
				Check: func(*terraform.State) error {
					config, _ := s.IntegrationConfig(id)
					if config["tlsCaCertificate"] != splunkCA || config["tlsHostnameCheck"] != "skip" {
						return fmt.Errorf("Act holds %v, want the pinned CA without the hostname check", config)
					}
					return nil
				},
			},
			{
				Config:   splunkWithTLS(""),
				PlanOnly: true,
			},
			{
				Config: splunkWithTLS("  tls_ca_certificate = \"\"\n"),
				Check: func(*terraform.State) error {
					if config, _ := s.IntegrationConfig(id); config["tlsCaCertificate"] != "" {
						return fmt.Errorf("Act still pins %q", config["tlsCaCertificate"])
					}
					return nil
				},
			},
		},
	})
}

func TestNewIntegrationSettingsAreCheckedAtPlan(t *testing.T) {
	cortex := pastedKeyKinds[0]
	tests := []struct {
		name   string
		config string
		want   string
	}{
		{
			name: "cortex cloud API URL outside paloaltonetworks.com",
			config: cortex.writeOnly(map[string]string{
				"api_url":        "https://api-acme.example.com",
				"api_key_id":     "7",
				"security_level": "standard",
			}, "key", 1),
			want: `Cortex Cloud API URL`,
		},
		{
			name: "cortex cloud key ID that is not a number",
			config: cortex.writeOnly(map[string]string{
				"api_url":        "https://api-acme.xdr.us.paloaltonetworks.com",
				"api_key_id":     "seven",
				"security_level": "standard",
			}, "key", 1),
			want: `numeric key ID`,
		},
		{
			name: "cortex cloud security level outside the closed list",
			config: cortex.writeOnly(map[string]string{
				"api_url":        "https://api-acme.xdr.us.paloaltonetworks.com",
				"api_key_id":     "7",
				"security_level": "Standard",
			}, "key", 1),
			want: `value must be one of`,
		},
		{
			name:   "splunk hostname check outside the closed list",
			config: splunkWithTLS("  tls_hostname_check = \"off\"\n"),
			want:   `value must be one of`,
		},
		{
			name: "cortex cloud key set both ways",
			config: requiredProviders + `
provider "act" {}
resource "act_cortex_cloud_integration" "this" {
  api_url            = "https://api-acme.xdr.us.paloaltonetworks.com"
  api_key_id         = "7"
  security_level     = "standard"
  api_key            = "a"
  api_key_wo         = "b"
  api_key_wo_version = 1
}
`,
			want: `api_key`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := fakeapi.Start(t)
			s.Setenv(t)
			resource.UnitTest(t, resource.TestCase{
				ProtoV6ProviderFactories: factories(),
				TerraformVersionChecks:   []tfversion.TerraformVersionCheck{tfversion.SkipBelow(tfversion.Version1_11_0)},
				Steps: []resource.TestStep{{
					Config:      test.config,
					PlanOnly:    true,
					ExpectError: regexp.MustCompile(test.want),
				}},
			})
		})
	}
}
