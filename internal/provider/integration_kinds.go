package provider

import (
	"errors"
	"regexp"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	openapi_types "github.com/oapi-codegen/runtime/types"

	"github.com/act-security/terraform-provider-act/internal/apigen"
	"github.com/act-security/terraform-provider-act/internal/client"
)

var (
	slackTokenPattern  = regexp.MustCompile(`^xoxb-`)
	jiraSitePattern    = regexp.MustCompile(`^https://([a-z0-9][a-z0-9-]*\.atlassian\.net|api\.atlassian\.com/ex/jira/[^/]+)/?$`)
	emailPattern       = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	wizEndpointPattern = regexp.MustCompile(`^https://api\.[a-z0-9][a-z0-9-]*\.(app\.wiz\.io|app\.wiz\.us|gov\.wiz\.io)(/.*)?$`)
	httpsPattern       = regexp.MustCompile(`^https://`)
	cortexAPIPattern   = regexp.MustCompile(`^https://api-[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.paloaltonetworks\.com/?$`)
	digitsPattern      = regexp.MustCompile(`^[0-9]+$`)
)

const (
	maxSecretLength         = 4096
	maxCertificateLength    = 32 * 1024
	maxCortexAPIKeyIDDigits = 64
)

var slackIntegration = integrationKind{
	name:        "slack",
	apiType:     apigen.InstallableIntegrationTypeSlack,
	title:       "Slack",
	description: "A Slack integration, connected with the bot token of a Slack app you create from the Act manifest. Act sends notifications to the channels a notification rule names. One per tenant.",
	secret: integrationSecretField{
		attr:        "bot_token",
		wire:        "botToken",
		description: "The app's Bot User OAuth Token, starting with `xoxb-`.",
		validators:  []validator.String{stringvalidator.RegexMatches(slackTokenPattern, "must start with xoxb-")},
	},
}

var jiraIntegration = integrationKind{
	name:        "jira",
	apiType:     apigen.InstallableIntegrationTypeJira,
	title:       "Jira",
	description: "A Jira Cloud integration, connected with a scoped Atlassian API token. Act creates and tracks Jira issues for its findings. One per tenant.",
	config: []integrationConfigField{
		{
			attr:        "base_url",
			wire:        "baseUrl",
			description: "Your Atlassian site URL, such as `https://acme.atlassian.net`. Changing it sends the API token again.",
			validators:  []validator.String{stringvalidator.RegexMatches(jiraSitePattern, "must be an Atlassian Cloud site URL")},
		},
		{
			attr:        "email",
			wire:        "email",
			description: "The email address of the Atlassian account that created the token. Changing it sends the API token again.",
			validators:  []validator.String{stringvalidator.RegexMatches(emailPattern, "must be an email address")},
		},
	},
	secret: integrationSecretField{
		attr:        "api_token",
		wire:        "apiToken",
		description: "A scoped Atlassian API token with `read:jira-work`, `write:jira-work` and `read:jira-user`.",
		validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
	},
}

var wizIntegration = integrationKind{
	name:        "wiz",
	apiType:     apigen.InstallableIntegrationTypeWiz,
	title:       "Wiz",
	description: "A Wiz integration, connected with a Wiz service account so Act can read its issues. One per tenant.",
	config: []integrationConfigField{
		{
			attr:        "client_id",
			wire:        "clientId",
			description: "The client ID of the Wiz service account. Changing it sends the client secret again.",
			validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
		},
		{
			attr:        "api_endpoint_url",
			wire:        "apiEndpointUrl",
			description: "Your Wiz API endpoint, such as `https://api.us17.app.wiz.io/graphql`. Changing it sends the client secret again.",
			validators:  []validator.String{stringvalidator.RegexMatches(wizEndpointPattern, "must be a Wiz API endpoint")},
		},
	},
	secret: integrationSecretField{
		attr:        "client_secret",
		wire:        "clientSecret",
		description: "The client secret of the Wiz service account.",
		validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
	},
}

var splunkIntegration = integrationKind{
	name:        "splunk",
	apiType:     apigen.InstallableIntegrationTypeSplunk,
	title:       "Splunk",
	description: "A Splunk integration that sends Act events as OCSF through the HTTP Event Collector. One per tenant.",
	config: []integrationConfigField{
		{
			attr:        "hec_url",
			wire:        "hecUrl",
			description: "Your public HTTP Event Collector URL, such as `https://http-inputs-acme.splunkcloud.com`. Changing it sends the HEC token again.",
			validators:  []validator.String{stringvalidator.RegexMatches(httpsPattern, "must be an https URL")},
		},
		{
			attr:         "tls_verification",
			wire:         "tlsVerification",
			description:  "How Act checks the HEC certificate: `verify` (default), `splunk_default_ca` for Splunk's default certificate, or `none`, which lets anyone between Act and Splunk read the token. Changing it sends the HEC token again.",
			validators:   []validator.String{stringvalidator.OneOf("verify", "splunk_default_ca", "none")},
			defaultValue: "verify",
		},
		{
			attr:        "tls_ca_certificate",
			wire:        "tlsCaCertificate",
			description: "The PEM certificate of the private CA that signed your HEC certificate. Act then trusts only that CA, unless `tls_verification` is `none`. Leave it out to keep the value Act holds; set it to `\"\"` to stop pinning a CA. Changing it sends the HEC token again.",
			validators:  []validator.String{stringvalidator.LengthAtMost(maxCertificateLength)},
			optional:    true,
		},
		{
			attr:        "tls_hostname_check",
			wire:        "tlsHostnameCheck",
			description: "Whether Act checks that the HEC certificate names the host in `hec_url`, when `tls_ca_certificate` is set: `check` (what Act does when it is not set) or `skip`. Leave it out to keep the value Act holds. Changing it sends the HEC token again.",
			validators:  []validator.String{stringvalidator.OneOf("check", "skip")},
			optional:    true,
		},
	},
	secret: integrationSecretField{
		attr:        "hec_token",
		wire:        "hecToken",
		description: "The HEC token, allowed to write to the index your notification rules name.",
		validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
	},
}

var cortexCloudIntegration = integrationKind{
	name:        "cortex_cloud",
	apiType:     apigen.InstallableIntegrationTypeCortexCloud,
	title:       "Cortex Cloud",
	description: "A Palo Alto Networks Cortex Cloud integration, connected with a Cortex API key so Act can read your assets and issues. One per tenant.",
	config: []integrationConfigField{
		{
			attr:        "api_url",
			wire:        "apiUrl",
			description: "Your Cortex Cloud API URL, such as `https://api-acme.xdr.us.paloaltonetworks.com`. In Cortex Cloud, open Settings > Configurations > API Keys and select Copy API URL. Changing it sends the API key again.",
			validators:  []validator.String{stringvalidator.RegexMatches(cortexAPIPattern, "must be a Cortex Cloud API URL starting with https://api-")},
		},
		{
			attr:        "api_key_id",
			wire:        "apiKeyId",
			description: "The number in the ID column of the key on the API Keys page. Changing it sends the API key again.",
			validators: []validator.String{
				stringvalidator.RegexMatches(digitsPattern, "must be the numeric key ID"),
				stringvalidator.LengthAtMost(maxCortexAPIKeyIDDigits),
			},
		},
		{
			attr:        "security_level",
			wire:        "securityLevel",
			description: "The security level you chose when you generated the key: `standard` or `advanced`. Changing it sends the API key again.",
			validators:  []validator.String{stringvalidator.OneOf("standard", "advanced")},
		},
	},
	secret: integrationSecretField{
		attr:        "api_key",
		wire:        "apiKey",
		description: "The Cortex Cloud API key, assigned the Viewer role or a custom role with View on Public API, Asset Inventory and Cases and Issues.",
		validators:  []validator.String{stringvalidator.LengthBetween(1, maxSecretLength)},
	},
}

func NewSlackIntegrationResource() resource.Resource {
	return &integrationResource{kind: slackIntegration}
}

func NewJiraIntegrationResource() resource.Resource {
	return &integrationResource{kind: jiraIntegration}
}

func NewWizIntegrationResource() resource.Resource { return &integrationResource{kind: wizIntegration} }

func NewSplunkIntegrationResource() resource.Resource {
	return &integrationResource{kind: splunkIntegration}
}

func NewCortexCloudIntegrationResource() resource.Resource {
	return &integrationResource{kind: cortexCloudIntegration}
}

func apigenEmail(value string) openapi_types.Email {
	return openapi_types.Email(value)
}

func asAPIError(err error, target **client.APIError) bool {
	return errors.As(err, target)
}
