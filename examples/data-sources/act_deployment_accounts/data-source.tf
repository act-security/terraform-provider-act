data "act_deployment_accounts" "failed" {
  deployment_id = act_aws_organization_deployment.this.id
  status        = "failed"
}

output "accounts_act_cannot_reach" {
  value = data.act_deployment_accounts.failed.account_ids
}
