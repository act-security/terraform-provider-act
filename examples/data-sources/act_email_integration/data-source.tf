data "act_email_integration" "this" {}

output "email_integration_id" {
  value = data.act_email_integration.this.id
}
