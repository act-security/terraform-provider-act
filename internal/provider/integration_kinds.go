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
	},
	secret: integrationSecretField{
		attr:        "hec_token",
		wire:        "hecToken",
		description: "The HEC token, allowed to write to the index your notification rules name.",
		validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
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

func apigenEmail(value string) openapi_types.Email {
	return openapi_types.Email(value)
}

func asAPIError(err error, target **client.APIError) bool {
	return errors.As(err, target)
}
