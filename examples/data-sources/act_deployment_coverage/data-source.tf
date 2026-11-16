check "act_organization_coverage" {
  data "act_deployment_coverage" "this" {
    deployment_id = act_aws_organization_deployment.this.id
  }

  assert {
    condition     = data.act_deployment_coverage.this.accounts_failed == 0
    error_message = "Act cannot reach ${data.act_deployment_coverage.this.accounts_failed} accounts of the organization."
  }
}
