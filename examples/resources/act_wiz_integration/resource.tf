variable "wiz_client_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

resource "act_wiz_integration" "this" {
  client_id                = "act-reader"
  api_endpoint_url         = "https://api.us17.app.wiz.io/graphql"
  client_secret_wo         = var.wiz_client_secret
  client_secret_wo_version = 1
}
