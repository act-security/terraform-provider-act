data "act_deployments" "failing" {
  cloud  = "aws"
  status = "failed"
}

output "failing_deployment_ids" {
  value = data.act_deployments.failing.ids
}
