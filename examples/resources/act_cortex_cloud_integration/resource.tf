variable "cortex_cloud_api_key" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_cortex_cloud_integration" "this" {
  api_url            = "https://api-acme.xdr.us.paloaltonetworks.com"
  api_key_id         = "7"
  security_level     = "standard"
  api_key_wo         = var.cortex_cloud_api_key
  api_key_wo_version = 1
}
