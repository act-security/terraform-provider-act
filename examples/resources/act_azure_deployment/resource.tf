data "act_azure_onboarding_parameters" "this" {
  directory_id    = "00000000-0000-0000-0000-000000000000"
  subscription_id = "11111111-1111-1111-1111-111111111111"
}

resource "azuread_service_principal" "act" {
  client_id    = data.act_azure_onboarding_parameters.this.act_app_client_id
  use_existing = true
}

module "act" {
  source = "act-security/act/azurerm"

  deployment_id        = data.act_azure_onboarding_parameters.this.deployment_id
  binding_marker       = data.act_azure_onboarding_parameters.this.binding_marker
  service_principal_id = azuread_service_principal.act.object_id
  subscription_id      = "11111111-1111-1111-1111-111111111111"
}

resource "act_azure_deployment" "this" {
  deployment_id        = data.act_azure_onboarding_parameters.this.deployment_id
  azure_tenant_id      = data.act_azure_onboarding_parameters.this.azure_tenant_id
  subscription_id      = module.act.subscription_id
  service_principal_id = module.act.service_principal_id
  tags                 = { team = "platform" }
}
