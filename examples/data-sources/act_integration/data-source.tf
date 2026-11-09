data "act_integration" "email" {
  type = "email"
}

output "email_integration_id" {
  value = data.act_integration.email.id
}
