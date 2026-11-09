data "act_integration_types" "all" {}

output "installable_types" {
  value = [for t in data.act_integration_types.all.types : t.type if t.installable]
}
