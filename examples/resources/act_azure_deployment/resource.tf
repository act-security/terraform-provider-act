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
