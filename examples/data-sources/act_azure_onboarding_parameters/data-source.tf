data "act_azure_onboarding_parameters" "this" {
  directory_id    = "00000000-0000-0000-0000-000000000000"
  subscription_id = "11111111-1111-1111-1111-111111111111"
}

output "act_admin_consent_url" {
  value = data.act_azure_onboarding_parameters.this.admin_consent_url
}

output "act_custom_role_name" {
  value = data.act_azure_onboarding_parameters.this.custom_role_name
}
