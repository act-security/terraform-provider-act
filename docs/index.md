---
page_title: "Provider: Act"
description: |-
  Use the Act provider to work with Act Security from Terraform.
---

# Act Provider

The Act provider connects Terraform to [Act Security](https://act.security). It signs in with an Act API key and finds the tenant and the regional API on its own, so the client ID and secret are all it needs.

## Getting started

1. In the Act console, open **Settings → API keys** and create an API key. Copy its client ID and client secret.
2. Export them in the shell or CI job that runs Terraform:

   ```shell
   export ACT_CLIENT_ID="<client id>"
   export ACT_CLIENT_SECRET="<client secret>"
   ```

3. Add the provider and run `terraform init`:

```terraform
terraform {
  required_providers {
    act = {
      source  = "act-security/act"
      version = "~> 0.3"
    }
  }
}

provider "act" {}
```

That is the whole configuration. You don't set a tenant, a region or an API URL: the provider reads the tenant from the API key and asks Act which regional API serves it.

To check the setup, read the [`act_current_identity`](https://registry.terraform.io/providers/act-security/act/latest/docs/data-sources/current_identity) data source. It returns the tenant, region and service account the provider signed in as.

## Authentication

| Argument | Environment variable | Required | Description |
|---|---|---|---|
| `client_id` | `ACT_CLIENT_ID` | Yes | The API key's client ID. |
| `client_secret` | `ACT_CLIENT_SECRET` | Yes | The API key's client secret. |
| `tenant_id` | `ACT_TENANT_ID` | No | The tenant you expect. The run fails if the key belongs to a different tenant. |

A value in the `provider` block wins over the environment variable. The schema below lists `client_id` and `client_secret` as optional only because either one can come from its environment variable instead.

Keep the client secret out of your configuration files. The environment variable is the simplest way. If you pass it in Terraform, use a sensitive variable:

```terraform
variable "act_client_secret" {
  type      = string
  sensitive = true
}

provider "act" {
  client_id     = "<client id>"
  client_secret = var.act_client_secret
  tenant_id     = "<tenant id>"
}
```

### API keys for plan and apply

Every API key has a role and an access level, both picked when you create it:

| Role | What the key reaches |
|---|---|
| All API areas | Deployments, integrations and notification rules |
| Terraform deployments | Deployments only |

| Access | What the key can do |
|---|---|
| Read | Read only |
| Read and write | Read, create, change and delete |

For deployments, create two API keys with the role **Terraform deployments**: a **Read** key for `terraform plan`, for example on pull requests, and a **Read and write** key for `terraform apply`. Only the apply job then holds a key that can change anything in Act.

The provider checks the key against the plan:

- **At plan**, when the plan creates, changes or destroys a resource that the key cannot write, the plan succeeds with the warning *The Act API key cannot apply this change*. It names the resource and the scope it needs, so a pull request plan with the Read key shows the full diff and tells you the apply needs the other key.
- **At apply**, the same check runs before the provider calls the Act API. With the wrong key the apply fails with that message and sends nothing to Act, instead of stopping halfway on a `403`.

The plan only warns because a provider cannot tell a `terraform plan` run from the plan step of a `terraform apply`, and the Read key is meant for plans.

The plan job runs with the Read key:

```shell
export ACT_CLIENT_ID="<read key client id>"
export ACT_CLIENT_SECRET="<read key client secret>"
terraform plan
```

The apply job runs with the Read and write key:

```shell
export ACT_CLIENT_ID="<read and write key client id>"
export ACT_CLIENT_SECRET="<read and write key client secret>"
terraform apply
```

| Resources | Scope a change needs |
|---|---|
| `act_aws_account_deployment`, `act_aws_organization_deployment` | `deployments:write` |
| `act_slack_integration`, `act_jira_integration`, `act_wiz_integration`, `act_splunk_integration`, `act_cortex_cloud_integration`, `act_notification_rule`, `act_notification_recipient` | `integrations:write` |

The [`act_current_identity`](https://registry.terraform.io/providers/act-security/act/latest/docs/data-sources/current_identity) data source lists the scopes the key holds.

### How the provider connects

The provider exchanges the API key at the Act STS (`auth.act.security`) for a short-lived token. The STS also tells it which regional API serves the tenant, such as `api.us1.act.security`, and the provider then talks only to that API. Tokens are renewed automatically, so long runs don't expire.

If your runners sit behind a firewall, allow outbound HTTPS to `auth.act.security` and to your region's `api.<region>.act.security`.

## Retries

The provider retries a request up to 4 times when the Act STS or API answers `429`, `502`, `503` or `504`, when the API marks an error as retryable, or when the connection fails. It waits with exponential backoff and honours `Retry-After` (or `X-Retry-After` when `Retry-After` is absent) up to 30 seconds. A `POST` is retried only when it carries an idempotency key, as creating an integration or a deployment does, so a retry never creates a second one. Certificate errors and requests the server rejected are never retried.

When the API answers `401`, the provider gets a new token once and repeats the request.

## Release signing

Every release is signed with the Act provider signing key, and every archive carries GitHub build provenance. To mirror the provider into a private registry, use the public key and fingerprint in [SECURITY.md](https://github.com/act-security/terraform-provider-act/blob/main/SECURITY.md). Report security issues there too.

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `client_id` (String) The API key's client ID, from Settings → API keys in the Act console. Required, here or in `ACT_CLIENT_ID`.
- `client_secret` (String, Sensitive) The API key's client secret. Required, here or in `ACT_CLIENT_SECRET`, which keeps it out of the configuration.
- `tenant_id` (String) The Act tenant ID, a lowercase UUID, here or in `ACT_TENANT_ID`. Not needed: the provider reads the tenant from the API key. When set, the provider fails if the key belongs to another tenant.
