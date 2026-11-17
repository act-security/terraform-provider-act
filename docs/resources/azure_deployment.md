---
page_title: "act_azure_deployment Resource - act"
subcategory: ""
description: |-
  Connects one Azure subscription or management group to Act through Act's multi-tenant app. Act checks the role assignments of its service principal before it stores anything. When Act's service principal is already in the directory but an Entra admin has not approved Act for this Act organization yet, the deployment is stored as pending_consent and the apply succeeds with a warning that carries the approval link.
---

# act_azure_deployment (Resource)

Connects one Azure subscription or management group to Act through Act's multi-tenant app. Act checks the role assignments of its service principal before it stores anything. When Act's service principal is already in the directory but an Entra admin has not approved Act for this Act organization yet, the deployment is stored as `pending_consent` and the apply succeeds with a warning that carries the approval link.

## Example Usage

Read the onboarding values first, look up Act's service principal with the tenant submodule, give it its roles with the Act module for Azure, then connect the subscription:

```terraform
variable "subscription_id" {
  type = string
}

data "act_azure_onboarding_parameters" "this" {
  directory_id    = "00000000-0000-0000-0000-000000000000"
  subscription_id = var.subscription_id
}

module "act_tenant" {
  source = "act-security/act/azurerm//modules/tenant"

  act_app_client_id = data.act_azure_onboarding_parameters.this.act_app_client_id
  consent_url       = data.act_azure_onboarding_parameters.this.admin_consent_url
  include_entra_id  = false
}

module "act" {
  source = "act-security/act/azurerm"

  deployment_id        = data.act_azure_onboarding_parameters.this.deployment_id
  binding_marker       = data.act_azure_onboarding_parameters.this.binding_marker
  service_principal_id = module.act_tenant.service_principal_id
  subscription_id      = var.subscription_id
}

resource "act_azure_deployment" "this" {
  deployment_id        = module.act.deployment_id
  azure_tenant_id      = module.act.azure_tenant_id
  subscription_id      = module.act.subscription_id
  service_principal_id = module.act.service_principal_id
  tags                 = { team = "platform" }
}
```

`data.act_azure_onboarding_parameters` is a read and creates nothing. Its `deployment_id` and `binding_marker` are stable, so a plan you run again shows no change.

Terraform never creates or owns Act's service principal: an Entra admin's approval of Act creates it in the directory. The tenant submodule, `act-security/act/azurerm//modules/tenant`, only looks it up from `act_app_client_id`. When it is not in the directory yet, the plan fails with the consent link; see [Entra admin approval](#entra-admin-approval). Set `include_entra_id` to the same value on the submodule and on the resource.

The Act module for Azure, `act-security/act/azurerm`, creates the custom role, puts `binding_marker` in its description and assigns the custom role and the built-in roles to the service principal at the subscription. Its `deployment_id`, `azure_tenant_id`, `subscription_id` and `service_principal_id` outputs depend on those role resources, so passing them to the resource makes Terraform finish the role assignments before Act checks them.

To connect a management group, set `management_group_id` instead of `subscription_id` on the data source and on the resource, and pass the management group to the module. It covers every subscription under the group, and `deletion_protection` defaults to `true`.

## Entra admin approval

Act reads Azure through its multi-tenant app, and an Entra admin of the directory approves that app for your Act organization once. The approval covers every later deployment of your Act organization in the same directory. Without `include_entra_id`, an Application Administrator or a Cloud Application Administrator can approve it. With `include_entra_id = true`, Act also asks for Microsoft Graph app roles, and only a Global Administrator or a Privileged Role Administrator can approve those.

The first time Act is used in a directory, its service principal does not exist yet. The tenant submodule then fails the plan with the consent link, the same link as `admin_consent_url` of the data source. An Entra admin opens it and approves Act, which creates the service principal, and the next plan goes through.

When the service principal already exists in the directory, because an Entra admin approved Act for another Act organization, but the approval for your Act organization is missing, the plan goes through and the apply stores the deployment with `status = "pending_consent"`:

1. The apply succeeds with a warning that carries `consent_url`.
2. An Entra admin opens the link and approves Act for your Act organization.
3. Act verifies the deployment on its own after the approval. The next refresh shows `status = "active"` and `consent_url = null`, and the plan shows no change.

`tenant_consented` of the data source tells you whether the directory has approved Act for your Act organization already. Turning on `include_entra_id` later can need a new approval for the Graph app roles: the apply then leaves the deployment `pending_consent` again with a new warning.

## Verification

Act checks the service principal's role assignments and the custom role's `binding_marker` before it stores anything. New role assignments can take several minutes to work everywhere in Azure, so while Act reports that they have not propagated yet, the provider asks again, backing off up to 30 seconds between attempts, for up to 10 minutes. A failure that cannot fix itself, such as a missing role assignment, stops once the same answer has come back for 30 seconds. A failed create stores nothing, so the next apply starts clean.

Use `timeouts` to cap the whole operation; the defaults are 12 minutes for create and update.

On success the apply prints a warning with the deployment's console link. It is not an error: it confirms that Act reached the subscription.

## When the role assignments break

If someone removes a role assignment or the custom role, the next refresh reports `status = "failed"` with a warning, and the plan updates the deployment in place. Once the configuration has fixed the assignments, the apply asks Act to verify it again and the deployment is active in the same apply. Set `reverify_on_failure = false` to keep the warning without the extra update. A deployment that is `pending_consent` is never verified by Terraform: it needs the approval, not a new check.

## Destroy

Destroying the resource disconnects the target: Act stops scanning and deletes what it held. The service principal and its role assignments stay in Azure, and the apply lists them in a warning. With `deletion_protection = true`, a plan that destroys or replaces the deployment fails before anything changes; changing `deployment_method`, the target or `azure_tenant_id` replaces it, so turn protection off and apply that first. To stop managing the deployment without disconnecting it, use a `removed` block with `lifecycle { destroy = false }` on Terraform 1.7 and later, or `terraform state rm`.

## State

Nothing in this resource is a secret. The state holds IDs, the consent link and the deployment's status. Act stores `service_principal_id` only once it verifies the deployment, so while the deployment is `pending_consent`, or right after an import, the provider keeps the value from your configuration instead of planning a change. The provider keeps the deployment's ETag in private state and sends it with every change, so a change made in the Act console between plan and apply stops the apply instead of being overwritten.

<!-- schema generated by tfplugindocs -->
## Schema

### Required

- `azure_tenant_id` (String) The Entra directory (Azure tenant) that owns the target, from `data.act_azure_onboarding_parameters`. Changing it replaces the deployment.
- `deployment_id` (String) The deployment ID Act issued for this target, from `data.act_azure_onboarding_parameters`. Act rejects any other value. Changing it replaces the deployment.
- `service_principal_id` (String) The object ID of Act's service principal in the directory. Pass `service_principal_id` from the Act module: it depends on the role assignments, so Terraform creates them first. Act stores it only once it verifies the deployment, so while the deployment is `pending_consent` or right after an import the provider keeps the configured value. Changing it updates the deployment in place and Act verifies it again.

### Optional

- `deletion_protection` (Boolean) When true, Act refuses to delete the deployment and a plan that destroys it fails. Defaults to `true` for a management group and `false` for a subscription.
- `deployment_method` (String) How the role assignments were made: `terraform` (default), `cli` or `manual`. Changing it replaces the deployment: on a protected deployment, set `deletion_protection = false` and apply that first, or the plan fails. When you import a deployment set up another way, set its method.
- `include_entra_id` (Boolean) When true, Act also reads Entra ID through Microsoft Graph. It needs the Graph app roles in `required_graph_app_role_ids` of the onboarding data source, and the approval then needs a Global Administrator or a Privileged Role Administrator. Defaults to `false`. Changing it updates the deployment in place and Act verifies it again.
- `management_group_id` (String) The Azure management group to connect, covering every subscription under it. Set this or `subscription_id`. Changing it replaces the deployment.
- `name` (String) The name Act shows for the deployment, 1 to 64 characters. Act picks one when you leave it out. Changing it updates the deployment in place.
- `reverify_on_failure` (Boolean) When the deployment is `failed`, plan a verification so the next apply makes it active again once the role assignments are fixed. It does nothing while the deployment is `pending_consent`. Defaults to `true`. Only the provider uses it.
- `subscription_id` (String) The Azure subscription to connect, a lowercase UUID. Set this or `management_group_id`. Changing it replaces the deployment.
- `tags` (Map of String) Act tags for the deployment, at most 50. They are not Azure tags.
- `timeouts` (Block, Optional) (see [below for nested schema](#nestedblock--timeouts))

### Read-Only

- `consent_url` (String) The link an Entra admin opens once to approve Act. Set while the deployment is `pending_consent`, null otherwise.
- `console_url` (String) The deployment's page in the Act console. Null when Act does not report one.
- `created_at` (String) When the deployment was created, in RFC 3339.
- `created_via` (String) `ui` or `api`. Null when Act does not know.
- `deployed_version` (String) The version Act detected.
- `error_code` (String) Why the deployment failed. Null unless failed.
- `error_message` (String) What Act saw when the deployment failed. Null unless failed.
- `id` (String) The deployment ID, equal to `deployment_id`.
- `status` (String) `active` when Act can use the service principal, `pending_consent` until an Entra admin approves Act in the directory, `failed` when Act cannot use it.
- `update_available` (Boolean) True when the role assignments are older than the version Act recommends.

<a id="nestedblock--timeouts"></a>
### Nested Schema for `timeouts`

Optional:

- `create` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours).
- `update` (String) A string that can be [parsed as a duration](https://pkg.go.dev/time#ParseDuration) consisting of numbers and unit suffixes, such as "30s" or "2h45m". Valid time units are "s" (seconds), "m" (minutes), "h" (hours).

## Import

Import by `subscription/<subscription-id>`, `management-group/<management-group-id>` or the deployment ID:

```shell
terraform import act_azure_deployment.this subscription/11111111-1111-1111-1111-111111111111
```

On Terraform 1.5 and later you can use an `import` block instead. When the onboarding data source returns `existing_deployment`, the target already has a deployment, for example one created in the Act console, and creating another fails with the `import` block to use.

```terraform
import {
  to = act_azure_deployment.this
  id = "management-group/mg-platform"
}
```
