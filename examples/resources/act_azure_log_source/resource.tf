module "act_logs" {
  source = "act-security/act/azurerm//modules/activity-logs"

  deployment_id        = act_azure_deployment.this.id
  service_principal_id = act_azure_deployment.this.service_principal_id
  location             = "westeurope"
  subscription_ids     = [var.subscription_id]
}

module "act_entra_logs" {
  source = "act-security/act/azurerm//modules/entra-logs"

  deployment_id         = act_azure_deployment.this.id
  eventhub_namespace_id = module.act_logs.namespace_id
}

resource "act_azure_log_source" "this" {
  deployment_id          = act_azure_deployment.this.id
  events_subscription_id = var.subscription_id
  activity_logs          = true
  entra_id_logs          = true

  depends_on = [module.act_logs, module.act_entra_logs]
}
