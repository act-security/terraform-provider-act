variable "cloudflare_api_token" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_cloudflare_integration" "this" {
  account_id           = "0123456789abcdef0123456789abcdef"
  api_token_wo         = var.cloudflare_api_token
  api_token_wo_version = 1
}
