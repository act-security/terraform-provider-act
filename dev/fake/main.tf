terraform {
  required_providers {
    act = {
      source = "act-security/act"
    }
  }
}

provider "act" {}

data "act_current_identity" "this" {}

output "tenant" {
  value = data.act_current_identity.this.tenant_id
}

output "region" {
  value = data.act_current_identity.this.region
}

output "principal" {
  value = data.act_current_identity.this.principal_id
}
