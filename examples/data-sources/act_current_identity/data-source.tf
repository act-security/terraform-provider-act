data "act_current_identity" "this" {}

output "act_tenant" {
  value = data.act_current_identity.this.tenant_display_name
}
