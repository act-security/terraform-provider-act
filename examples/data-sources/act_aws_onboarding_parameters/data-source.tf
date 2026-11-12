data "act_aws_onboarding_parameters" "this" {
  account_id = "111111111111"
}

output "act_role_name" {
  value = data.act_aws_onboarding_parameters.this.role_name
}

output "act_external_id" {
  value = data.act_aws_onboarding_parameters.this.external_id
}
