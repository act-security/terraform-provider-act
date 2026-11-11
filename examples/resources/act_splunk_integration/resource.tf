variable "splunk_hec_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_splunk_integration" "this" {
  hec_url              = "https://http-inputs-acme.splunkcloud.com"
  hec_token_wo         = var.splunk_hec_token
  hec_token_wo_version = 1
}
